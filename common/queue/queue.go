package queue

import (
	"errors"
)

func NewQueue(capacity int) *Queue {
	return &Queue{
		capacity: capacity,
		data:     make([]interface{}, capacity),
	}
}

// FIFO queue
type Queue struct {
	bi       int // begin index
	ei       int // end index
	capacity int
	size     int
	data     []interface{}
}

func (q *Queue) Len() int {
	return q.size
}

func (q *Queue) Peek(index int) interface{} {
	index = (q.bi + index) % q.capacity
	return q.data[index]
}

func (q *Queue) Dequeue() (interface{}, error) {
	if q.size == 0 {
		return nil, errors.New("no elements in queue")
	}
	r := q.data[q.bi]
	q.bi = (q.bi + 1) % q.capacity
	q.size--
	return r, nil
}

func (q *Queue) Enqueue(v interface{}) error {
	if q.size == q.capacity {
		return errors.New("queue is full")
	}
	q.data[q.ei] = v
	q.ei = (q.ei + 1) % q.capacity
	q.size++
	return nil
}

func (q *Queue) Clear() {
	for q.Len() > 0 {
		q.Dequeue()
	}
}
