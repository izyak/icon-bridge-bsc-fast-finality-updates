package queue

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestQueueImplementation(t *testing.T) {

	notificationQueue := NewQueue(5)

	notificationQueue.Enqueue(1)
	notificationQueue.Enqueue(2)
	notificationQueue.Enqueue(3)
	notificationQueue.Enqueue(4)
	notificationQueue.Enqueue(5)
	// queue full
	assert.Equal(t, 5, notificationQueue.Len())

	err := notificationQueue.Enqueue(5)
	assert.Error(t, err)

	// start to pop
	a, err := notificationQueue.Dequeue()
	assert.NoError(t, err)
	assert.Equal(t, a, 1)
	assert.Equal(t, notificationQueue.Len(), 4)

	notificationQueue.Dequeue()
	notificationQueue.Dequeue()
	notificationQueue.Dequeue()
	notificationQueue.Dequeue()
	_, err = notificationQueue.Dequeue()
	assert.Error(t, err)

	// half filled queue

	notificationQueue.Enqueue(1)
	notificationQueue.Enqueue(2)
	notificationQueue.Enqueue(3)
	a, _ = notificationQueue.Dequeue()
	assert.Equal(t, a, 1)

	notificationQueue.Enqueue(4)
	assert.Equal(t, notificationQueue.Len(), 3)

	a, _ = notificationQueue.Dequeue()
	assert.Equal(t, a, 2)

	notificationQueue.Clear()
	assert.Equal(t, notificationQueue.Len(), 0)


}
