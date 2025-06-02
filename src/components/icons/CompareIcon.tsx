import React from 'react';

interface IconProps extends React.SVGProps<SVGSVGElement> {
  size?: number | string;
}

export const CompareIcon: React.FC<IconProps> = ({ size = 24, className = '', ...props }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={`text-gray-700 ${className}`}
    {...props}
  >
    <polyline points="16 3 21 3 21 8"></polyline>
    <line x1="4" y1="20" x2="21" y2="3"></line>
    <polyline points="8 21 3 21 3 16"></polyline>
    <line x1="15" y1="15" x2="3" y2="3"></line> {/* Custom line to show comparison aspect */}
    <line x1="21" y1="9" x2="9" y2="21"></line>
  </svg>
);
