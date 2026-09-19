import { useState } from "react";

import "../index.css";
import "./Navbar.css";

import extensions from "../data/extensions.json";

function Navbar() {
    const [showInfo, setShowInfo] = useState(false);
    const [selected, setSelected] = useState(null);
    const [search, setSearch] = useState("");

    const filteredExtensions = extensions.filter((item) =>
        item.extension.toLowerCase().includes(search.toLowerCase()) ||
        item.name.toLowerCase().includes(search.toLowerCase()) ||
        item.description.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <>
            <header className="topbar">

                <div className="page-title">
                    <h1 className="khan">
                        Security Overview
                    </h1>

                    <p>
                        Real-time endpoint security monitoring
                    </p>
                </div>

                <button
                    className="info-btn"
                    onClick={() => setShowInfo(true)}
                    title="File Extension Information"
                >
                    ⓘ
                </button>

            </header>


            {showInfo && (
                <div
                    className="info-modal-overlay"
                    onClick={() => setShowInfo(false)}
                >

                    <div
                        className="info-modal"
                        onClick={(e) => e.stopPropagation()}
                    >

                        {/* MODAL HEADER */}

                        <div className="info-modal-header">

                            <div>
                                <h2>File Extension Guide</h2>

                                <p>
                                    Understand common file types in simple terms.
                                </p>
                            </div>

                            <button
                                className="info-close"
                                onClick={() => setShowInfo(false)}
                            >
                                ×
                            </button>

                        </div>


                        {/* SEARCH BAR */}

                        <div className="info-search">

                            <span className="search-icon">
                                ⌕
                            </span>

                            <input
                                type="text"
                                placeholder="Search file extension..."
                                value={search}
                                onChange={(e) => {
                                    setSearch(e.target.value);
                                    setSelected(null);
                                }}
                            />

                            {search && (
                                <button
                                    className="search-clear"
                                    onClick={() => setSearch("")}
                                    aria-label="Clear search"
                                >
                                    ×
                                </button>
                            )}

                        </div>


                        {/* EXTENSION GRID */}

                        <div className="extension-grid">

                            {filteredExtensions.map((item) => (

                                <button
                                    key={item.extension}
                                    className={`extension-card ${selected === item.extension
                                            ? "active"
                                            : ""
                                        }`}
                                    onClick={() =>
                                        setSelected(
                                            selected === item.extension
                                                ? null
                                                : item.extension
                                        )
                                    }
                                >

                                    <span className="extension">
                                        {item.extension}
                                    </span>

                                    <span className="extension-name">
                                        {item.name}
                                    </span>

                                    {selected === item.extension && (
                                        <span className="extension-description">
                                            {item.description}
                                        </span>
                                    )}

                                </button>

                            ))}

                        </div>


                        {/* NO RESULTS */}

                        {filteredExtensions.length === 0 && (
                            <div className="no-results">
                                No file extension found.
                            </div>
                        )}

                    </div>

                </div>
            )}

        </>
    );
}

export default Navbar;