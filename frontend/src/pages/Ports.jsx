import { useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";
import API from "../services/api";
import "./Ports.css";
import "../index.css";

function getRiskClass(level) {
    if (!level) return "risk-low";

    const value = level.toLowerCase();

    if (value === "high" || value === "critical") return "risk-high";
    if (value === "medium") return "risk-medium";

    return "risk-low";
}

function getProtocolRowClass(protocol) {
    if (!protocol) return "";

    return protocol.toUpperCase() === "TCP"
        ? "port-row-tcp"
        : protocol.toUpperCase() === "UDP"
            ? "port-row-udp"
            : "";
}

function Ports() {
    const [ports, setPorts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState(false);
    const [error, setError] = useState(null);
    const [lastScan, setLastScan] = useState(null);

    const loadPorts = async () => {
        try {
            setError(null);

            const response = await API.get("/api/ports/");
            setPorts(response.data.ports || []);
        } catch (err) {
            console.error("Port API Error:", err);
            setError("Unable to connect to Port Scanner API.");
        } finally {
            setLoading(false);
        }
    };

    const scanPorts = async () => {
        try {
            setScanning(true);
            setError(null);

            const response = await API.post("/api/ports/scan/");

            setPorts(response.data.ports || []);
            setLastScan(
                response.data.timestamp || new Date().toISOString()
            );
        } catch (err) {
            console.error("Port Scan Error:", err);
            setError("Unable to perform port scan.");
        } finally {
            setScanning(false);
        }
    };

    useEffect(() => {
        loadPorts();
    }, []);

    const totalPorts = ports.length;

    const tcpPorts = ports.filter(
        p => p.protocol === "TCP"
    ).length;

    const udpPorts = ports.filter(
        p => p.protocol === "UDP"
    ).length;

    const highRisk = ports.filter(
        p =>
            p.risk_level === "HIGH" ||
            p.risk_level === "CRITICAL"
    ).length;

    const mediumRisk = ports.filter(
        p => p.risk_level === "MEDIUM"
    ).length;

    const lowRisk = ports.filter(
        p => p.risk_level === "LOW"
    ).length;

    return (
        <div className="dashboard">
            <Sidebar />

            <main className="main-content">
                <Navbar />

                <section className="ports-section">

                    {/* ==============================
                        HEADER
                    ============================== */}
                    <div className="section-header">
                        <div>
                            <h1 className="khan">
                                Network Ports
                            </h1>

                            <p>
                                TCP listening and UDP bound ports on this machine
                            </p>
                        </div>

                        <div className="port-header-actions">

                        </div>
                    </div>

                    {/* ==============================
                        CONNECTION ERROR
                    ============================== */}
                    {error ? (
                        <div className="error-box">
                            {error}
                            <br />

                            <button
                                className="retry-button"
                                onClick={loadPorts}
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

                                    <div>
                                        <div className="stat-label">
                                            Total Ports
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : totalPorts}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">
                                        T
                                    </div>

                                    <div>
                                        <div className="stat-label">
                                            TCP Ports
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : tcpPorts}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">
                                        U
                                    </div>

                                    <div>
                                        <div className="stat-label">
                                            UDP Ports
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : udpPorts}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card">
                                    <div className="stat-icon">
                                        ▲
                                    </div>

                                    <div>
                                        <div className="stat-label">
                                            High Risk
                                        </div>

                                        <div className="stat-value">
                                            {loading ? "—" : highRisk}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass-card stat-card risk-overview">
                                    <div className="stat-icon">
                                        ◇
                                    </div>

                                    <div>
                                        <div className="stat-label">
                                            Risk Overview
                                        </div>

                                        <div className="risk-values">
                                            <span className="high-dot">
                                                ● High {highRisk}
                                            </span>

                                            <span className="medium-dot">
                                                ● Medium {mediumRisk}
                                            </span>

                                            <span className="low-dot">
                                                ● Low {lowRisk}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                            </div>

                            {/* ==============================
                                ACTIVE NETWORK PORTS
                            ============================== */}
                            <div className="ports-table-header">
                                <div>
                                    <h3 className="khan">
                                        Active Network Ports
                                    </h3>

                                    <p>
                                        Currently detected TCP and UDP sockets
                                    </p>
                                </div>

                                {lastScan && (
                                    <span className="last-scan">
                                        Last scan:{" "}
                                        {new Date(
                                            lastScan
                                        ).toLocaleTimeString()}
                                    </span>
                                )}
                            </div>

                            {loading ? (
                                <div className="empty-state">
                                    Scanning network ports...
                                </div>
                            ) : ports.length === 0 ? (
                                <div className="empty-state">
                                    No active network ports detected.
                                </div>
                            ) : (
                                <div className="table-container">
                                    <table className="events-table ports-table">
                                        <thead>
                                            <tr>
                                                <th>Port</th>
                                                <th>Protocol</th>
                                                <th>State</th>
                                                <th>Local IP</th>
                                                <th>Service</th>
                                                <th>Process</th>
                                                <th>PID</th>
                                                <th>Risk</th>
                                            </tr>
                                        </thead>

                                        <tbody>
                                            {ports.map((port, index) => (
                                                <tr
                                                    key={`${port.protocol}-${port.port}-${port.pid}-${index}`}
                                                    className={getProtocolRowClass(
                                                        port.protocol
                                                    )}
                                                >
                                                    <td>
                                                        <strong className="port-number">
                                                            {port.port}
                                                        </strong>
                                                    </td>

                                                    <td>
                                                        <span
                                                            className={`protocol-badge protocol-${port.protocol?.toLowerCase()}`}
                                                        >
                                                            {port.protocol}
                                                        </span>
                                                    </td>

                                                    <td>
                                                        {port.state}
                                                    </td>

                                                    <td className="ip-address">
                                                        {port.local_ip || "—"}
                                                    </td>

                                                    <td>
                                                        {port.service || "Unknown"}
                                                    </td>

                                                    <td>
                                                        {port.process_name || "Unknown"}
                                                    </td>

                                                    <td>
                                                        {port.pid || "—"}
                                                    </td>

                                                    <td>
                                                        <span
                                                            className={`risk-badge ${getRiskClass(
                                                                port.risk_level
                                                            )}`}
                                                        >
                                                            {port.risk_level || "UNKNOWN"}
                                                        </span>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}

                            {/* ==============================
                                FOOTER
                            ============================== */}
                            <div className="ports-footer">
                                <span>
                                    Showing{" "}
                                    <strong>{ports.length}</strong>{" "}
                                    active ports
                                </span>

                                <span>
                                    TCP: <strong>{tcpPorts}</strong>
                                    {" | "}
                                    UDP: <strong>{udpPorts}</strong>
                                </span>
                            </div>
                        </>
                    )}
                </section>
            </main>
        </div>
    );
}

export default Ports;