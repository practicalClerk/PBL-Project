import React from "react";
import { Link } from "react-router-dom";

export default function Navbar() {
  return (
    <nav className="w-full flex justify-between items-center p-4 bg-white shadow-md">
      <h1 className="text-3xl font-bold text-blue-600">AI Fraud Detection</h1>
      <div className="space-x-6">
        <Link to="/" className="text-lg font-semibold text-gray-700 hover:text-blue-600">Home</Link>
        <Link to="/about" className="text-lg font-semibold text-gray-700 hover:text-blue-600">About</Link>
        <Link to="/contact" className="text-lg font-semibold text-gray-700 hover:text-blue-600">Contact</Link>
      </div>
    </nav>
  );
}
