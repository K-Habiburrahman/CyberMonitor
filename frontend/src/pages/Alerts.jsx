import { useEffect, useState } from "react";
import "../index.css";
import "./Alerts.css";

import { getAlerts } from "../services/api";

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

function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const loadAlerts = async () => {
        try {
            const data = await getAlerts();

            setAlerts(data.alerts || []);
            setError(null);
        } catch (err) {
            console.error(err);
            setError("Unable to connect to CyberMonitor API.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadAlerts();

        const interval = setInterval(
            loadAlerts,
            5000
        );

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="dashboard">
            <Sidebar />

            <main className="main-content">
                <Navbar />

                <div className="alerts-page">

                    <div className="alerts-header">
                        <div>
                            <h1 className="khan">Security Alerts</h1>
                            <p>
                                Detected security threats and suspicious activity
                            </p>
                        </div>

                    </div>

                    {error ? (
                        <div className="error-box">
                            {error}
                            <br />

                            <button
                                className="retry-button"
                                onClick={loadAlerts}
                            >
                                Retry Connection
                            </button>
                        </div>
                    ) : (
                        <>
                            {loading ? (
                                <div className="empty-state">
                                    Loading security alerts...
                                </div>
                            ) : alerts.length === 0 ? (
                                <div className="empty-state">
                                    No security alerts detected.
                                </div>
                            ) : (
                                <div className="alerts-list">

                                    {alerts.map((alert) => (
                                        <div
                                            className="glass-card alert-card"
                                            key={alert.id}
                                        >

                                            <div className="alert-top">

                                                <div>
                                                    <div className="alert-process">
                                                        {alert.process_name ||
                                                            "System Event"}
                                                    </div>

                                                    <div className="alert-rule">
                                                        {alert.rule ||
                                                            "Security Detection"}
                                                    </div>
                                                </div>

                                                <span
                                                    className={`risk-badge ${getRiskClass(
                                                        alert.risk_level
                                                    )}`}
                                                >
                                                    {alert.risk_level || "SAFE"}
                                                </span>

                                            </div>

                                            <div className="alert-message">
                                                {alert.message}
                                            </div>

                                            <div className="alert-details">

                                                <span>
                                                    Risk Score:{" "}
                                                    <strong>
                                                        {alert.risk_score ?? 0}/100
                                                    </strong>
                                                </span>

                                                <span>
                                                    PID:{" "}
                                                    <strong>
                                                        {alert.pid ?? "—"}
                                                    </strong>
                                                </span>

                                                <span>
                                                    {alert.timestamp
                                                        ? new Date(
                                                            alert.timestamp
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
                                                        )
                                                        : "—"}
                                                </span>

                                            </div>

                                        </div>
                                    ))}

                                </div>
                            )}
                        </>
                    )}

                </div>
            </main>
        </div>
    );
}

export default Alerts;
