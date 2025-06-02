import React from 'react';

interface IconProps extends React.SVGProps<SVGSVGElement> {
  size?: number | string;
}

export const ChevronDownIcon: React.FC<IconProps> = ({ size = 20, className = '', ...props }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={`text-gray-700 ${className}`} // Default color, can be overridden by className prop
    {...props}
  >
    <polyline points="6 9 12 15 18 9"></polyline>
  </svg>
);
