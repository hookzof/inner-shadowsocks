package main

import (
	"log"
	"sync"
	"time"
)

type Scheduler struct {
	maxFail   int
	status    []bool
	failCount []int
	succChan  chan int
	failChan  chan int
	lock      sync.Mutex
	verbose   bool
}

func (s *Scheduler) log(f string, v ...interface{}) {
	if s.verbose {
		log.Printf(f, v...)
	}
}

func (s *Scheduler) get() int {
	for i, v := range s.status {
		if v {
			s.log("[Schedule] Get server %d.", i)
			return i
		}
	}
	s.lock.Lock()
	for i := range s.status {
		s.status[i] = true
		s.failCount[i] = 0
	}
	s.lock.Unlock()
	s.log("[Schedule] All servers down. Restart all of them. Get 0")
	return 0
}

func (s *Scheduler) reportSuccess(id int) {
	s.log("[Schedule] %d success.", id)
	s.succChan <- id
}

func (s *Scheduler) reportFail(id int) {
	s.log("[Schedule] %d fail.", id)
	s.failChan <- id
}

func (s *Scheduler) init(n, maxFail, chanBuf, recoverTime int, verbose bool) {
	s.verbose = verbose
	s.maxFail = maxFail
	s.status = make([]bool, n)
	for i := range s.status {
		s.status[i] = true
	}
	s.failCount = make([]int, n)
	s.succChan, s.failChan = make(chan int, chanBuf), make(chan int, chanBuf)
	go s.process(recoverTime)
	s.log("[Schedule] Init. Maxfail=%d, Recover_time=%d sec, channel_buffer_size=%d.", maxFail, recoverTime, chanBuf)
}

func (s *Scheduler) process(recoverTime int) {
	for {
		select {
		case succ := <-s.succChan:
			s.lock.Lock()
			s.status[succ] = true
			s.failCount[succ] = 0
			s.lock.Unlock()
		case fail := <-s.failChan:
			s.lock.Lock()
			if s.status[fail] == true {
				if s.failCount[fail] >= s.maxFail {
					s.failCount[fail] = 0
					s.status[fail] = false
					go func(locker *sync.Mutex, timer *time.Timer) {
						<-timer.C
						locker.Lock()
						s.status[fail] = true
						s.failCount[fail] = 0
						locker.Unlock()
						s.log("[Schedule] Server %d up due to time exceed.", fail)
					}(&s.lock, time.NewTimer(time.Second*time.Duration(recoverTime)))
					s.log("[Schedule] Server %d down.", fail)
				} else {
					s.failCount[fail]++
					s.log("[Schedule] %d fail count: %d.", fail, s.failCount[fail])
				}
			}
			s.lock.Unlock()
		}
	}
}
