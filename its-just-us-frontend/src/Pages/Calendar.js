import React, { useState, useEffect } from "react";
import api from "../services/api";

function Calendar() {
  const [events, setEvents] = useState([]);
  const [newEvent, setNewEvent] = useState({ title: "", date: "" });

  useEffect(() => {
    api.get("/calendar").then((response) => setEvents(response.data));
  }, []);

  const handleEventSubmit = async (e) => {
    e.preventDefault();
    await api.post("/calendar", newEvent);
    setNewEvent({ title: "", date: "" });
    api.get("/calendar").then((response) => setEvents(response.data));
  };

  return (
    <div>
      <form onSubmit={handleEventSubmit}>
        <input type="text" placeholder="Title" value={newEvent.title} onChange={(e) => setNewEvent({ ...newEvent, title: e.target.value })} />
        <input type="date" value={newEvent.date} onChange={(e) => setNewEvent({ ...newEvent, date: e.target.value })} />
        <button type="submit">Add Event</button>
      </form>
      {events.map((event) => (
        <p key={event.id}>{event.title} - {event.date}</p>
      ))}
    </div>
  );
}

export default Calendar;