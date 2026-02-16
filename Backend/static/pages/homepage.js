import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaShieldAlt, FaGlobe, FaBriefcase, FaVideo } from "react-icons/fa";

export default function homepage() {
  const navigate = useNavigate(); // For redirecting with the button

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center text-center p-8">
      {/* Navigation Bar */}
      <nav className="w-full flex justify-between items-center p-4 bg-white shadow-md">
        <h1 className="text-3xl font-bold text-blue-600 flex items-center">
          <FaShieldAlt className="mr-2 text-blue-700" /> AI Fraud Detection
        </h1>
        <div className="space-x-6">
          <Link to="/" className="text-lg font-semibold text-gray-700 hover:text-blue-600">Home</Link>
          <Link to="/about" className="text-lg font-semibold text-gray-700 hover:text-blue-600">About</Link>
          <Link to="/contact" className="text-lg font-semibold text-gray-700 hover:text-blue-600">Contact</Link>
          <button 
            onClick={() => navigate("/PHISHING")} 
            className="px-5 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700"
          >
            Get Started
          </button>
        </div>
      </nav>
      
      {/* Hero Section */}
      <section className="flex flex-col md:flex-row items-center justify-center py-20 px-6">
        <div className="text-left max-w-xl">
          <h2 className="text-5xl font-extrabold text-blue-700 leading-tight">Protecting You from Fraud</h2>
          <p className="text-gray-600 mt-4 text-lg">
            AI-driven fraud detection system to safeguard users from scams, phishing, and fake content.
          </p>
          <button 
            onClick={() => navigate("/PHISHING")} 
            className="mt-6 px-6 py-3 bg-orange-500 text-white font-bold text-lg rounded-lg shadow-lg hover:bg-orange-600"
          >
            Start Scanning
          </button>
        </div>
        <img src="/fraud-detection-illustration.png" alt="Fraud Monitoring" className="w-1/2 max-w-lg" />
      </section>
      
      {/* Models Section */}
      <section className="w-full flex flex-wrap justify-center gap-8 mt-10">
        <div className="bg-white p-6 rounded-lg shadow-lg w-80 text-center">
          <FaGlobe className="text-blue-700 text-4xl mb-2 mx-auto" />
          <h3 className="text-xl font-semibold text-blue-700">Phishing Website Detection</h3>
          <p className="text-gray-600">Detect fraudulent websites using AI.</p>
          <Link to="/PHISHING" className="mt-4 block px-4 py-2 bg-blue-500 text-white font-semibold rounded-lg hover:bg-blue-600">
            Test Now
          </Link>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-lg w-80 text-center">
          <FaBriefcase className="text-blue-700 text-4xl mb-2 mx-auto" />
          <h3 className="text-xl font-semibold text-blue-700">Fake Job Posting Detection</h3>
          <p className="text-gray-600">Analyze job postings for potential fraud.</p>
          <Link to="/fakejobs" className="mt-4 block px-4 py-2 bg-blue-500 text-white font-semibold rounded-lg hover:bg-blue-600">
            Click here to experience
          </Link>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-lg w-80 text-center">
          <FaVideo className="text-blue-700 text-4xl mb-2 mx-auto" />
          <h3 className="text-xl font-semibold text-blue-700">Deepfake & AI Content Detection</h3>
          <p className="text-gray-600">Identify AI-generated fake media.</p>
          <Link to="/deepfake" className="mt-4 block px-4 py-2 bg-blue-500 text-white font-semibold rounded-lg hover:bg-blue-600">
            Test Now
          </Link>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="mt-10 text-gray-600 text-sm">
        2025 AI Fraud Detection | Project In Progress | <a href="#" className="text-blue-600 hover:underline">Privacy Policy</a>
      </footer>
    </div>
  );
}
