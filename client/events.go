package client

import (
	"sync"
)

// Events is a stream of values the application listens to. Callbacks run on the library's
// goroutines, one at a time per stream of a computer, in the order sent; the application moves
// to its own goroutine itself. A callback that panics is skipped. The zero value is ready.
type Events[T any] struct {
	mu   sync.RWMutex
	subs map[int]func(T)
	next int
}

// Subscribe calls f for every value from now on; the returned function unsubscribes.
func (e *Events[T]) Subscribe(f func(T)) (cancel func()) {
	e.mu.Lock()
	if e.subs == nil {
		e.subs = map[int]func(T){}
	}
	id := e.next
	e.next++
	e.subs[id] = f
	e.mu.Unlock()
	return func() {
		e.mu.Lock()
		delete(e.subs, id)
		e.mu.Unlock()
	}
}

// Chan is Subscribe as a channel. Values queue without limit, so a slow reader never holds up
// the stream; cancel stops the delivery and closes the channel.
func (e *Events[T]) Chan() (events <-chan T, cancel func()) {
	var (
		mu    sync.Mutex
		queue []T
		wake  = make(chan struct{}, 1)
		stop  = make(chan struct{})
		out   = make(chan T)
	)
	unsub := e.Subscribe(func(v T) {
		mu.Lock()
		queue = append(queue, v)
		mu.Unlock()
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	go func() {
		defer close(out)
		for {
			mu.Lock()
			var v T
			ok := len(queue) > 0
			if ok {
				v = queue[0]
				queue = queue[1:]
			}
			mu.Unlock()
			if !ok {
				select {
				case <-wake:
					continue
				case <-stop:
					return
				}
			}
			select {
			case out <- v:
			case <-stop:
				return
			}
		}
	}()
	var once sync.Once
	return out, func() { once.Do(func() { unsub(); close(stop) }) }
}

func (e *Events[T]) emit(v T) {
	e.mu.RLock()
	fs := make([]func(T), 0, len(e.subs))
	for _, f := range e.subs {
		fs = append(fs, f)
	}
	e.mu.RUnlock()
	for _, f := range fs {
		func() {
			defer func() { _ = recover() }()
			f(v)
		}()
	}
}
