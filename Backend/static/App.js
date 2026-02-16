import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import HomePage from "./pages/homepage";
import PhishingPage from "./pages/PHSHING";  // Ensure you have this file
import FakeJobPage from "./pages/fakejob";    // Ensure you have this file
import DeepFakePage from "./pages/deepfake";  // Ensure you have this file

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/PHISHING" element={<PhishingPage />} />
        <Route path="/fakejobs" element={<FakeJobPage />} />
        <Route path="/deepfake" element={<DeepFakePage />} />
      </Routes>
    </Router>
  );
}

export default App;
