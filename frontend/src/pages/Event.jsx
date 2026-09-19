import { useEffect, useState } from "react";

import "../index.css";
import "./Event.css";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";

function Event() {
    const [events, setEvents] = useState([]);
    const [filteredEvents, setFilteredEvents] = useState([]);
    const [activeFilter, setActiveFilter] = useState("ALL");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const API_BASE_URL =
        import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

    const fetchEvents = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await fetch(
                `${API_BASE_URL}/api/events/?limit=100`
            );

            if (!response.ok) {
                throw new Error("Failed to fetch events");
            }

            const data = await response.json();

            setEvents(data.events || []);
            setFilteredEvents(data.events || []);
        } catch (err) {
            console.error("Events fetch error:", err);

            setEvents([]);
            setFilteredEvents([]);
            setError("Unable to load security events.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchEvents();
    }, []);

    useEffect(() => {
        if (activeFilter === "ALL") {
            setFilteredEvents(events);
            return;
        }

        let filtered = [];

        if (activeFilter === "PROCESS") {
            filtered = events.filter(
                (event) =>
                    event.event_type &&
                    event.event_type.startsWith("PROCESS")
            );
        }

        if (activeFilter === "NETWORK") {
            filtered = events.filter(
                (event) =>
                    event.event_type &&
                    event.event_type.startsWith("NETWORK")
            );
        }

        if (activeFilter === "FILE") {
            filtered = events.filter(
                (event) =>
                    event.event_type &&
                    event.event_type.startsWith("FILE")
            );
        }

        if (activeFilter === "PORT") {
            filtered = events.filter(
                (event) =>
                    event.event_type &&
                    event.event_type.startsWith("PORT")
            );
        }

        setFilteredEvents(filtered);
    }, [activeFilter, events]);

    const formatTimestamp = (timestamp) => {
        if (!timestamp) {
            return "-";
        }

        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch {
            return timestamp;
        }
    };

    const getRiskClass = (riskLevel) => {
        if (!riskLevel) {
            return "risk-low";
        }

        const level = riskLevel.toLowerCase();

        if (level === "high") {
            return "risk-high";
        }

        if (level === "medium") {
            return "risk-medium";
        }

        return "risk-low";
    };

    const getSource = (event) => {
        if (event.process_name) {
            return event.process_name;
        }

        if (event.file_path) {
            return event.file_path;
        }

        if (event.remote_ip) {
            return event.remote_ip;
        }

        return "-";
    };

    const filters = [
        "ALL",
        "PROCESS",
        "NETWORK",
        "FILE",
        "PORT",
    ];

    return (
        <div className="dashboard">
            <Sidebar />

            <main className="main-content">
                <Navbar />

                <div className="events-page">
                    {/* ==========================================
                        PAGE HEADER
                    ========================================== */}
                    <div className="topbar">
                        <div className="page-title">
                            <h1 className="khan">Events</h1>
                            <p>
                                Complete security activity timeline
                            </p>
                        </div>
                    </div>

                    {/* ==========================================
                        FILTERS
                    ========================================== */}
                    <div className="event-filters">
                        {filters.map((filter) => (
                            <button
                                key={filter}
                                className={`event-filter ${activeFilter === filter ? "active" : ""
                                    }`}
                                onClick={() => setActiveFilter(filter)}
                                disabled={loading}
                            >
                                {filter}
                            </button>
                        ))}
                    </div>

                    {/* ==========================================
                        LOADING STATE
                    ========================================== */}
                    {loading && (
                        <div className="events-loading">
                            Loading security events...
                        </div>
                    )}

                    {/* ==========================================
                        CONNECTION ERROR
                        Same pattern as Ports.jsx
                    ========================================== */}
                    {!loading && error ? (
                        <div className="error-box">
                            {error}
                            <br />

                            <button
                                className="retry-button"
                                onClick={fetchEvents}
                            >
                                Retry Connection
                            </button>
                        </div>
                    ) : (
                        !loading && (
                            <div className="glass-card events-card">
                                {/* ==============================
                                    SUCCESS STATE
                                ============================== */}
                                <div className="section-header">
                                    <h2>Security Events</h2>

                                    <span className="event-count">
                                        {filteredEvents.length} events
                                    </span>
                                </div>

                                {/* ==============================
                                    EMPTY STATE
                                ============================== */}
                                {filteredEvents.length === 0 && (
                                    <div className="empty-state">
                                        No security events found.
                                    </div>
                                )}

                                {/* ==============================
                                    EVENTS TABLE
                                ============================== */}
                                {filteredEvents.length > 0 && (
                                    <div className="table-container">
                                        <table className="events-table">
                                            <thead>
                                                <tr>
                                                    <th>Time</th>
                                                    <th>Event</th>
                                                    <th>Source</th>
                                                    <th>PID</th>
                                                    <th>Risk</th>
                                                    <th>Rule</th>
                                                    <th>Message</th>
                                                </tr>
                                            </thead>

                                            <tbody>
                                                {filteredEvents.map((event) => (
                                                    <tr key={event.id}>
                                                        <td className="event-time">
                                                            {formatTimestamp(
                                                                event.timestamp
                                                            )}
                                                        </td>

                                                        <td>
                                                            <span className="event-type-badge">
                                                                {event.event_type ||
                                                                    "-"}
                                                            </span>
                                                        </td>

                                                        <td className="event-source">
                                                            {getSource(event)}
                                                        </td>

                                                        <td className="event-pid">
                                                            {event.pid ?? "-"}
                                                        </td>

                                                        <td>
                                                            <span
                                                                className={`risk-badge ${getRiskClass(
                                                                    event.risk_level
                                                                )}`}
                                                            >
                                                                {event.risk_level ||
                                                                    "SAFE"}
                                                            </span>
                                                        </td>

                                                        <td className="event-rule">
                                                            {event.rule || "-"}
                                                        </td>

                                                        <td className="event-message">
                                                            <span className="event-message-text">
                                                                {event.message ||
                                                                    "-"}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )
                    )}
                </div>
            </main>
        </div>
    );
}

export default Event;
