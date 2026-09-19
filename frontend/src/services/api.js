import axios from "axios";

const API = axios.create({
    baseURL: "http://127.0.0.1:8000",
    headers: {
        "Content-Type": "application/json",
    },
});

export const getStatistics = async () => {
    const response = await API.get("/api/statistics/");
    return response.data;
};

export const getAlerts = async () => {
    const response = await API.get("/api/alerts/");
    return response.data;
};

export const getEvents = async () => {
    const response = await API.get("/api/events/");
    return response.data;
};

// ============================================================
// PORT SCANNER
// ============================================================

export const getPorts = async () => {
    const response = await API.get("/api/ports/");
    return response.data;
};

export const scanPorts = async () => {
    const response = await API.post("/api/ports/scan/");
    return response.data;
};

export default API;