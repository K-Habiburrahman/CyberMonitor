import { useNavigate } from "react-router-dom";

import "../index.css";

function Sidebar() {

    const navigate = useNavigate();

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


            <button
                className="nav-item"
                onClick={() => navigate("/")}
            >
                <span className="nav-icon">⌂</span>
                <span>Dashboard</span>
            </button>


            {/* PORTS */}

            <button
                className="nav-item"
                onClick={() => navigate("/ports")}
            >
                <span className="nav-icon">⌁</span>
                <span>Ports</span>
            </button>


            {/* ALERTS */}

            <button
                className="nav-item"
                onClick={() => navigate("/alerts")}
            >
                <span className="nav-icon">!</span>
                <span>Alerts</span>
            </button>


            {/* THREATS */}

            <button className="nav-item"
                onClick={() => navigate("/threats")}
            >
                <span className="nav-icon">◈</span>
                <span>Threats</span>
            </button>


            {/* EVENTS */}

            <button
                className="nav-item"
                onClick={() => navigate("/events")}
            >
                <span className="nav-icon">◉</span>
                <span>Events</span>
            </button>

        </aside>

    );

}

export default Sidebar;