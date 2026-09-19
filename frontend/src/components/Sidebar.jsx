import { useNavigate, useLocation } from "react-router-dom";

import "../index.css";

function Sidebar() {
    const navigate = useNavigate();
    const location = useLocation();

    return (
        <aside className="sidebar">

            <div className="logo">
                <div className="logo-icon">
                    CM
                </div>
                <h2>
                    Cyber<span>Monitor</span>
                </h2>
            </div>

            <div className="nav-title">
                Security
            </div>

            {/* DASHBOARD */}
            <button
                className={`nav-item ${location.pathname === "/" ? "active" : ""}`}
                onClick={() => navigate("/")}
            >
                <span className="nav-icon">⌂</span>
                <span>Dashboard</span>
            </button>

            {/* PORTS */}
            <button
                className={`nav-item ${location.pathname === "/ports" ? "active" : ""}`}
                onClick={() => navigate("/ports")}
            >
                <span className="nav-icon">⌁</span>
                <span>Ports</span>
            </button>

            {/* ALERTS */}
            <button
                className={`nav-item ${location.pathname === "/alerts" ? "active" : ""}`}
                onClick={() => navigate("/alerts")}
            >
                <span className="nav-icon">!</span>
                <span>Alerts</span>
            </button>

            {/* THREATS */}
            <button
                className={`nav-item ${location.pathname === "/threats" ? "active" : ""}`}
                onClick={() => navigate("/threats")}
            >
                <span className="nav-icon">◈</span>
                <span>Threats</span>
            </button>

            {/* EVENTS */}
            <button
                className={`nav-item ${location.pathname === "/events" ? "active" : ""}`}
                onClick={() => navigate("/events")}
            >
                <span className="nav-icon">◉</span>
                <span>Events</span>
            </button>

        </aside>
    );
}

export default Sidebar;