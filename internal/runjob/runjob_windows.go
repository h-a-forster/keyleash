//go:build windows

package runjob

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = modKernel32.NewProc("IsProcessInJob")
)

// Supported reports whether job objects are available.
func Supported() bool { return procIsProcessInJob.Find() == nil }

type job struct {
	h        windows.Handle
	released bool
}

// Manager holds one job object per run pass. It is safe for concurrent use.
type Manager struct {
	killOnClose bool
	mu          sync.Mutex
	jobs        map[string]*job
	closed      bool
}

// New returns a manager. With killOnClose, closing the manager (or the
// daemon exiting) terminates every member process.
func New(killOnClose bool) *Manager {
	if !Supported() {
		return nil
	}
	return &Manager{killOnClose: killOnClose, jobs: map[string]*job{}}
}

// Confine creates the job for id and places process pid (whose creation
// time must be startTime, in Unix nanoseconds, so a reused PID is never
// confined by mistake) into it. The job forbids breakaway, so every process
// pid starts from now on is a member as well. On error no job is kept.
func (m *Manager) Confine(id string, pid int, startTime int64) error {
	if m == nil {
		return ErrUnsupported
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("runjob: open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(ph)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(ph, &creation, &exit, &kernel, &user); err != nil {
		return fmt.Errorf("runjob: process times %d: %w", pid, err)
	}
	if creation.Nanoseconds() != startTime {
		return fmt.Errorf("runjob: process %d is not the bound process (pid reused)", pid)
	}
	jh, err := windows.CreateJobObject(nil, nil) // unnamed: only the daemon holds it
	if err != nil {
		return fmt.Errorf("runjob: create job: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(jh)
		}
	}()
	// No JOB_OBJECT_LIMIT_BREAKAWAY_OK / SILENT_BREAKAWAY_OK: members cannot
	// start processes outside the job.
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if m.killOnClose {
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	if _, err := windows.SetInformationJobObject(jh, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("runjob: set job limits: %w", err)
	}
	if err := windows.AssignProcessToJobObject(jh, ph); err != nil {
		return fmt.Errorf("runjob: assign process %d: %w", pid, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrNoJob
	}
	if _, dup := m.jobs[id]; dup {
		// The process is in this job now as well; keep it so it stays
		// confined, under a key no pass id can have.
		m.jobs[fmt.Sprintf("%s#%d", id, len(m.jobs))] = &job{h: jh, released: true}
		ok = true
		return fmt.Errorf("runjob: a job for %s already exists", id)
	}
	m.jobs[id] = &job{h: jh}
	ok = true
	return nil
}

func inJob(h windows.Handle, pid int) (bool, error) {
	ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false, fmt.Errorf("runjob: open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(ph)
	var result int32
	r, _, e := procIsProcessInJob.Call(uintptr(ph), uintptr(h), uintptr(unsafe.Pointer(&result)))
	if r == 0 {
		return false, fmt.Errorf("runjob: IsProcessInJob: %w", e)
	}
	return result != 0, nil
}

// Member reports whether pid is in the job of id. An unknown id is
// (false, ErrNoJob).
func (m *Manager) Member(id string, pid int) (bool, error) {
	if m == nil {
		return false, ErrUnsupported
	}
	m.mu.Lock()
	j, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return false, ErrNoJob
	}
	return inJob(j.h, pid)
}

// MemberOfAny reports whether pid is in any job the manager holds,
// including jobs of passes that have ended but still have live members.
// Any error is returned (callers treat it as "member": fail closed).
func (m *Manager) MemberOfAny(pid int) (bool, error) {
	if m == nil {
		return false, ErrUnsupported
	}
	m.mu.Lock()
	hs := make([]windows.Handle, 0, len(m.jobs))
	for _, j := range m.jobs {
		hs = append(hs, j.h)
	}
	m.mu.Unlock()
	for _, h := range hs {
		in, err := inJob(h, pid)
		if err != nil || in {
			return true, err
		}
	}
	return false, nil
}

// basicAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type basicAccounting struct {
	TotalUserTime, TotalKernelTime                     int64
	ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses                uint32
	ActiveProcesses, TotalTerminatedProcesses          uint32
}

func activeProcesses(h windows.Handle) (uint32, error) {
	var info basicAccounting
	if err := windows.QueryInformationJobObject(h, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return 0, err
	}
	return info.ActiveProcesses, nil
}

// Sweep marks the jobs whose pass is no longer active (active(id) false)
// as released, and closes released jobs that have no live member left.
// Jobs with live members keep confining them.
func (m *Manager) Sweep(active func(id string) bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, j := range m.jobs {
		if !j.released && !active(baseID(id)) {
			j.released = true
		}
		if !j.released {
			continue
		}
		if n, err := activeProcesses(j.h); err == nil && n == 0 {
			windows.CloseHandle(j.h)
			delete(m.jobs, id)
		}
	}
}

// Len returns the number of jobs held.
func (m *Manager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs)
}

// Close closes every job handle (terminating members with killOnClose).
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for id, j := range m.jobs {
		windows.CloseHandle(j.h)
		delete(m.jobs, id)
	}
}

func baseID(id string) string {
	for i := 0; i < len(id); i++ {
		if id[i] == '#' {
			return id[:i]
		}
	}
	return id
}
