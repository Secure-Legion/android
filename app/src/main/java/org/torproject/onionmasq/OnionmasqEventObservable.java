package org.torproject.onionmasq;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import org.torproject.onionmasq.events.OnionmasqEvent;

class OnionmasqEventObservable extends ViewModel {
    private final MutableLiveData<OnionmasqEvent> event;
    public OnionmasqEventObservable() {
        event = new MutableLiveData<>();
    }

    public void update(OnionmasqEvent event) {
        this.event.postValue(event);
    }

    public MutableLiveData<OnionmasqEvent> getEvent() {
        return event;
    }
}

