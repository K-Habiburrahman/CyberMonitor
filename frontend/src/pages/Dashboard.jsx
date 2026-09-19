import { useEffect, useState } from "react";
import "../index.css";
import "./Dashboard.css";

import {
    getStatistics,
    getEvents,
} from "../services/api";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";

function getRiskClass(level) {
    if (!level) {
        return "risk-low";
    }

    const value = level.toLowerCase();

    if (value === "high" || value === "critical") {
        return "risk-high";
    }

    if (value === "medium") {
        return "risk-medium";
    }

    return "risk-low";
}

function getEventRowClass(eventType) {
    if (!eventType) {
        return "";
    }

    switch (eventType.toUpperCase()) {
        case "FILE_CREATED":
            return "event-created";
        case "FILE_MODIFIED":
            return "event-modified";
        case "FILE_DELETED":
            return "event-deleted";
        case "FILE_RENAMED":
            return "event-renamed";
        case "FILE_RESTORED":
            return "event-restored";
        default:
            return "";
    }
}

function Dashboard({ onNavigate }) {
    const [statistics, setStatistics] = useState(null);
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const loadDashboard = async () => {
        try {
            const [
                statisticsData,
                eventsData,
            ] = await Promise.all([
                getStatistics(),
                getEvents(),
            ]);

            setStatistics(statisticsData);
            setEvents(eventsData.events || []);
            setError(null);
        } catch (err) {
            console.error(err);
            setError("Unable to connect to CyberMonitor API.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadDashboard();

        const interval = setInterval(
            loadDashboard,
            5000
        );

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="dashboard">
            <Sidebar onNavigate={onNavigate} />

            <main className="main-content">
                <Navbar />

                {error ? (
                    <div className="error-box">
                        {error}
                        <br />
                        <button
                            className="retry-button"
                            onClick={loadDashboard}
                        >
                            Retry Connection
                        </button>
                    </div>
                ) : (
                    <>
                        {/* ==============================
                            STATISTICS
                        ============================== */}
                        <div className="stats-grid">
                            <div className="glass-card stat-card">
                                <div className="stat-icon">
                                    ◈
                                </div>
                                <div className="stat-label">
                                    Total Events
                                </div>
                                <div className="stat-value">
                                    {loading
                                        ? "—"
                                        : statistics?.total_events ?? 0}
                                </div>
                            </div>

                            <div className="glass-card stat-card">
                                <div className="stat-icon">
                                    !
                                </div>
                                <div className="stat-label">
                                    Security Alerts
                                </div>
                                <div className="stat-value">
                                    {loading
                                        ? "—"
                                        : statistics?.total_alerts ?? 0}
                                </div>
                            </div>

                            <div className="glass-card stat-card">
                                <div className="stat-icon">
                                    ▲
                                </div>
                                <div className="stat-label">
                                    High Risk
                                </div>
                                <div className="stat-value">
                                    {loading
                                        ? "—"
                                        : statistics?.high_risk ?? 0}
                                </div>
                            </div>

                            <div className="glass-card stat-card">
                                <div className="stat-icon">
                                    ◇
                                </div>
                                <div className="stat-label">
                                    Medium Risk
                                </div>
                                <div className="stat-value">
                                    {loading
                                        ? "—"
                                        : statistics?.medium_risk ?? 0}
                                </div>
                            </div>

                            <div className="glass-card stat-card">
                                <div className="stat-icon">
                                    ✓
                                </div>
                                <div className="stat-label">
                                    Low Risk
                                </div>
                                <div className="stat-value">
                                    {loading
                                        ? "—"
                                        : statistics?.low_risk ?? 0}
                                </div>
                            </div>
                        </div>

                        {/* ==============================
                            EVENTS
                        ============================== */}
                        <section className="glass-card section-card">
                            <div className="section-header">
                                <h2 className="khan">
                                    Recent Security Events
                                </h2>
                                <span>
                                    Latest 20
                                </span>
                            </div>

                            {events.length === 0 ? (
                                <div className="empty-state">
                                    No events recorded.
                                </div>
                            ) : (
                                <div className="table-container">
                                    <table className="events-table">
                                        <thead>
                                            <tr>
                                                <th>Event</th>
                                                <th>Process</th>
                                                <th>File / Details</th>
                                                <th>Risk</th>
                                                <th>Level</th>
                                                <th>Timestamp</th>
                                            </tr>
                                        </thead>

                                        <tbody>
                                            {events
                                                .slice(0, 20)
                                                .map((event) => (
                                                    <tr
                                                        key={event.id}
                                                        className={`event-row ${getEventRowClass(
                                                            event.event_type
                                                        )}`}
                                                    >
                                                        <td className="event-type">
                                                            {event.event_type}
                                                        </td>

                                                        <td>
                                                            {event.process_name ||
                                                                "—"}
                                                        </td>

                                                        <td>
                                                            {event.file_path ? (
                                                                <div className="file-details">
                                                                    <div className="file-name">
                                                                        {event.file_path.split(/[\\/]/).pop()}
                                                                    </div>
                                                                    <div className="file-path">
                                                                        {event.file_path}
                                                                    </div>
                                                                </div>
                                                            ) : (
                                                                event.message || "—"
                                                            )}
                                                        </td>

                                                        <td>
                                                            {event.risk_score ?? 0}
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

                                                        <td>
                                                            {new Date(
                                                                event.timestamp
                                                            ).toLocaleString(
                                                                "en-IN",
                                                                {
                                                                    day: "2-digit",
                                                                    month: "short",
                                                                    year: "numeric",
                                                                    hour: "2-digit",
                                                                    minute: "2-digit",
                                                                    second: "2-digit",
                                                                    hour12: true,
                                                                }
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </section>
                    </>
                )}
            </main>
        </div>
    );
}

export default Dashboard;
