import React from 'react';

interface CinematicHeroBackgroundProps {
  isFocused?: boolean;
}

export function CinematicHeroBackground({ isFocused = false }: CinematicHeroBackgroundProps) {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none select-none" aria-hidden="true">
      {/* 1. Deep Atmospheric Ambient Radial Glows */}
      <div
        className={`absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[520px] w-[520px] sm:h-[700px] sm:w-[700px] rounded-full transition-all duration-700 blur-[130px] opacity-25 dark:opacity-40 ${
          isFocused ? 'scale-110 bg-[#0055FF]/40' : 'bg-[#0055FF]/20'
        }`}
      />
      <div className="absolute top-12 left-10 h-72 w-72 rounded-full bg-[#FF263F]/10 blur-[110px] opacity-30" />
      <div className="absolute top-24 right-10 h-80 w-80 rounded-full bg-[#00E5FF]/15 blur-[120px] opacity-25" />

      {/* 2. Cyber Perspective Grid Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:36px_36px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_40%,#000_70%,transparent_100%)] opacity-40 dark:opacity-20" />

      {/* 3. Subtle Animated Network Nodes & Interconnected Lines (SVG) */}
      <svg className="absolute inset-0 w-full h-full opacity-35 dark:opacity-45" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="cyberLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#0055FF" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#00E5FF" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#0055FF" stopOpacity="0.1" />
          </linearGradient>
        </defs>

        {/* Network Vector Connections */}
        <line x1="15%" y1="20%" x2="40%" y2="35%" stroke="url(#cyberLineGrad)" strokeWidth="1" strokeDasharray="4 6" />
        <line x1="85%" y1="25%" x2="60%" y2="38%" stroke="url(#cyberLineGrad)" strokeWidth="1" strokeDasharray="4 6" />
        <line x1="30%" y1="65%" x2="50%" y2="50%" stroke="url(#cyberLineGrad)" strokeWidth="1" strokeDasharray="3 5" />
        <line x1="70%" y1="65%" x2="50%" y2="50%" stroke="url(#cyberLineGrad)" strokeWidth="1" strokeDasharray="3 5" />

        {/* Floating Glowing Nodes */}
        <circle cx="15%" cy="20%" r="3" fill="#00E5FF" className="animate-pulse" />
        <circle cx="40%" cy="35%" r="2" fill="#0055FF" />
        <circle cx="85%" cy="25%" r="3.5" fill="#00E5FF" className="animate-pulse" style={{ animationDuration: '3s' }} />
        <circle cx="60%" cy="38%" r="2.5" fill="#FF263F" className="animate-pulse" style={{ animationDuration: '2.5s' }} />
        <circle cx="30%" cy="65%" r="2" fill="#0055FF" />
        <circle cx="70%" cy="65%" r="2" fill="#00E5FF" />

        {/* Concentric Scanning Wave Radar Ring behind input */}
        <circle
          cx="50%"
          cy="48%"
          r="160"
          stroke="#0055FF"
          strokeWidth="1"
          strokeDasharray="6 8"
          className="opacity-20 animate-spin"
          style={{ animationDuration: '30s', transformOrigin: '50% 48%' }}
        />
        <circle
          cx="50%"
          cy="48%"
          r="240"
          stroke="#00E5FF"
          strokeWidth="1"
          strokeDasharray="8 12"
          className="opacity-15 animate-spin"
          style={{ animationDuration: '45s', transformOrigin: '50% 48%' }}
        />
      </svg>
    </div>
  );
}
