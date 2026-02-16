import React from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function fakejob() {
  return (
    <div className="min-h-screen bg-gray-100">
      <Navbar />
      <div className="p-10 text-center">
        <h2 className="text-3xl font-bold text-blue-700">Fake Job Posting Detection</h2>
        <p className="text-gray-600 mt-4">Upload a job description to analyze for potential fraud.</p>
        <input type="file" className="mt-4 px-4 py-2 border rounded-lg" />
        <button className="ml-4 px-4 py-2 bg-blue-500 text-white rounded-lg">Analyze</button>
      </div>
      <Footer />
    </div>
  );
}
