// Package runjob confines the process trees of `keyleash run` sessions
// (spec §12). On Windows each run pass gets its own job object, created and
// held by the daemon, into which the bound `keyleash run` process is placed
// when its pass is issued; everything that process starts afterwards is a
// member too, and the job does not allow breakaway, so no descendant can
// leave it, however its parent chain looks later (an intermediate parent
// exiting does not matter). Membership is then the confinement test: the
// daemon asks the kernel whether a caller is in one of its jobs.
//
// Jobs stay open after their pass ends for as long as any member process is
// alive, so processes that outlive `keyleash run` stay confined. They end
// with the daemon: a restarted daemon holds none (with KillOnClose the
// member processes are terminated when the daemon exits).
//
// Other platforms have no implementation: Supported reports false and New
// returns nil; the daemon then falls back to the parent-process walk and
// fails closed on errors.
package runjob

import "errors"

// ErrUnsupported is returned where job objects are not available.
var ErrUnsupported = errors.New("runjob: process confinement jobs are not supported on this platform")

// ErrNoJob is returned for an id the manager holds no job for.
var ErrNoJob = errors.New("runjob: no such job")
