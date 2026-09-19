import { useEffect, useState } from "react";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";
import API from "../services/api";
import "../index.css";
import "./Threats.css";

function getRiskClass(level) {
    if (!level) return "risk-low";

    const value = level.toLowerCase();

    if (value === "high" || value === "critical") {
        return "risk-high";
    }

    if (value === "medium") {
        return "risk-medium";
    }

    return "risk-low";
}

function Threats() {
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const loadThreats = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await API.get("/api/threats/?limit=100");
            setThreats(response.data.threats || []);
        } catch (err) {
            console.error("Threat API Error:", err);
            setError("Unable to load threats.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadThreats();
    }, []);

    const highThreats = threats.filter(
        (threat) =>
            threat.risk_level === "HIGH" ||
            threat.risk_level === "CRITICAL"
    ).length;

    const processThreats = threats.filter(
        (threat) =>
            threat.event_type &&
            threat.event_type.startsWith("PROCESS")
    ).length;

    const networkThreats = threats.filter(
        (threat) =>
            threat.event_type &&
            threat.event_type.startsWith("NETWORK")
    ).length;

    const getSource = (threat) => {
        if (threat.process_name) {
            return threat.process_name;
        }

        if (threat.file_path) {
            return threat.file_path;
        }

        if (threat.remote_ip) {
            return threat.remote_ip;
        }

        return "-";
    };

    const formatTimestamp = (timestamp) => {
        if (!timestamp) {
            return "-";
        }

        try {
            return new Date(timestamp).toLocaleString();
        } catch {
            return timestamp;
        }
    };

    return (
        <div className="dashboard">
            <Sidebar />

            <main className="main-content">
                <Navbar />

                <div className="threats-page">
                    <div className="topbar">
                        <div className="page-title">
                            <h1 className="khan">Threats</h1>
                            <p>
                                Detected high-risk security threats
                            </p>
                        </div>
                    </div>

                    {error ? (
                        <div className="error-box">
                            {error}
                            <br />

                            <button
                                className="retry-button"
                                onClick={loadThreats}
                            >
                                Retry Connection
                            </button>
                        </div>
                    ) : (
                        <>
                            {/* THREAT STATISTICS */}
                            <div className="stats-grid">
                                <div className="glass-card stat-card">
                                    <div className="stat-icon">⚠</div>

                                    <div>
                                        <div className="stat-label">
                                            Total Threats
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : threats.length}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">▲</div>

                                    <div>
                                        <div className="stat-label">
                                            High Risk
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : highThreats}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">◈</div>

                                    <div>
                                        <div className="stat-label">
                                            Process Threats
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : processThreats}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">⌁</div>

                                    <div>
                                        <div className="stat-label">
                                            Network Threats
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : networkThreats}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* THREATS TABLE */}
                            <div className="glass-card threats-card">
                                <div className="section-header">
                                    <div>
                                        <h2>Detected Threats</h2>
                                        <p>
                                            High-risk security events identified
                                            by CyberMonitor
                                        </p>
                                    </div>

                                    <span className="event-count">
                                        {threats.length} threats
                                    </span>
                                </div>

                                {loading ? (
                                    <div className="empty-state">
                                        Loading threats...
                                    </div>
                                ) : threats.length === 0 ? (
                                    <div className="empty-state">
                                        <div className="threat-empty-icon">
                                            ✓
                                        </div>

                                        <h3>No Threats Detected</h3>

                                        <p>
                                            CyberMonitor has not detected any
                                            high-risk security threats.
                                        </p>
                                    </div>
                                ) : (
                                    <div className="table-container">
                                        <table className="events-table">
                                            <thead>
                                                <tr>
                                                    <th>Time</th>
                                                    <th>Threat</th>
                                                    <th>Source</th>
                                                    <th>PID</th>
                                                    <th>Risk</th>
                                                    <th>Rule</th>
                                                    <th>Message</th>
                                                </tr>
                                            </thead>

                                            <tbody>
                                                {threats.map((threat) => (
                                                    <tr key={threat.id}>
                                                        <td className="event-time">
                                                            {formatTimestamp(
                                                                threat.timestamp
                                                            )}
                                                        </td>

                                                        <td>
                                                            <span className="threat-type-badge">
                                                                {threat.event_type ||
                                                                    "-"}
                                                            </span>
                                                        </td>

                                                        <td className="event-source">
                                                            {getSource(threat)}
                                                        </td>

                                                        <td className="event-pid">
                                                            {threat.pid ?? "-"}
                                                        </td>

                                                        <td>
                                                            <span
                                                                className={`risk-badge ${getRiskClass(
                                                                    threat.risk_level
                                                                )}`}
                                                            >
                                                                {threat.risk_level ||
                                                                    "HIGH"}
                                                            </span>
                                                        </td>

                                                        <td className="event-rule">
                                                            {threat.rule || "-"}
                                                        </td>

                                                        <td className="event-message">
                                                            <span className="event-message-text">
                                                                {threat.message ||
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
                        </>
                    )}
                </div>
            </main>
        </div>
    );
}

export default Threats;
