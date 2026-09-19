import { BrowserRouter, Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Ports from "./pages/Ports";
import Alerts from "./pages/Alerts";
import Event from "./pages/Event";
import Threats from "./pages/Threats";

import "./index.css";

function App() {
    return (
        <BrowserRouter>

            <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/ports" element={<Ports />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/events" element={<Event />} />
                <Route path="/threats" element={<Threats />} />
            </Routes>

        </BrowserRouter>
    );
}

export default App;
