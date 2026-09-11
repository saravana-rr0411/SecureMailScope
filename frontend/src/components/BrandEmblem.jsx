import React from 'react';

export default function BrandEmblem({ className = "w-8 h-8" }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="40" height="40" rx="8" fill="#0F172A" />
      <path
        d="M10 14C10 12.8954 10.8954 12 12 12H28C29.1046 12 30 12.8954 30 14V26C30 27.1046 29.1046 28 28 28H12C10.8954 28 10 27.1046 10 26V14Z"
        stroke="#94A3B8"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M10 14L20 21L30 14"
        stroke="#6366F1"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="20" cy="21" r="3.5" fill="#0F172A" stroke="#10B981" strokeWidth="1.5" />
      <path d="M20 19.5V22.5M18.5 21H21.5" stroke="#10B981" strokeWidth="1.2" strokeLinecap="round" />
      <path
        d="M27 24L31 28M30 25.5C30.8284 25.5 31.5 24.8284 31.5 24C31.5 23.1716 30.8284 22.5 30 22.5C29.1716 22.5 28.5 23.1716 28.5 24C28.5 24.8284 29.1716 25.5 30 25.5Z"
        stroke="#38BDF8"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
