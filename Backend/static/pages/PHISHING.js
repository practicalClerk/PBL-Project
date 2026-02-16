import React, { useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function PHISHING() {
  const [url, setUrl] = useState("");

  const checkPhishing = () => {
    alert(`Checking phishing status for: ${url}`);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <Navbar />
      <div className="p-10 text-center">
        <h2 className="text-3xl font-bold text-blue-700">Phishing Website Detection</h2>
        <p className="text-gray-600 mt-4">Enter a website URL to check for phishing threats.</p>
        <input
          type="text"
          placeholder="Enter URL"
          className="mt-4 px-4 py-2 border rounded-lg"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button onClick={checkPhishing} className="ml-4 px-4 py-2 bg-blue-500 text-white rounded-lg">
          Check
        </button>
      </div>
      <Footer />
    </div>
  );
}
