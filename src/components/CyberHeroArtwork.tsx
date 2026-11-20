import React from 'react';
import { CyberMascot } from './CyberMascot';

interface CyberHeroArtworkProps {
  className?: string;
  isScanning?: boolean;
}

/**
 * Adaptive Transparent 3D Cybersecurity Hero Artwork
 * Features SM-Sentinel mascot + holographic security shield + scanning radar lens + floating network nodes.
 * 100% transparent background with zero rectangular borders or white frames.
 * Automatically adapts to Dark (#000000) and Light (#FFFFFF) themes.
 */
export function CyberHeroArtwork({ className = '', isScanning = false }: CyberHeroArtworkProps) {
  return (
    <div
      className={`relative flex items-center justify-center select-none ${className}`}
      aria-hidden="true"
    >
      {/* 1. Behind-Mascot Holographic Shield (Pure Transparent SVG) */}
      <svg
        viewBox="0 0 240 240"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="absolute w-[220px] h-[220px] sm:w-[260px] sm:h-[260px] pointer-events-none drop-shadow-[0_0_20px_rgba(0,85,255,0.3)]"
      >
        <defs>
          <linearGradient id="heroShieldGlow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0055FF" stopOpacity="0.4" />
            <stop offset="50%" stopColor="#00E5FF" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#0055FF" stopOpacity="0.05" />
          </linearGradient>

          <linearGradient id="heroBorderGlow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00E5FF" />
            <stop offset="50%" stopColor="#0055FF" />
            <stop offset="100%" stopColor="#FF263F" />
          </linearGradient>
        </defs>

        {/* Concentric Pulsing Radar Waves */}
        <circle
          cx="120"
          cy="120"
          r="105"
          stroke="#0055FF"
          strokeWidth="1.2"
          strokeDasharray="8 6"
          className="opacity-35 animate-spin"
          style={{ animationDuration: '24s', transformOrigin: '120px 120px' }}
        />
        <circle
          cx="120"
          cy="120"
          r="80"
          stroke="#00E5FF"
          strokeWidth="1"
          strokeDasharray="4 6"
          className="opacity-30 animate-spin"
          style={{ animationDuration: '16s', transformOrigin: '120px 120px' }}
        />

        {/* 3D Holographic Shield Outline */}
        <path
          d="M120 28 L185 58 C185 130 155 178 120 206 C85 178 55 130 55 58 Z"
          fill="url(#heroShieldGlow)"
          stroke="url(#heroBorderGlow)"
          strokeWidth="2.5"
          className="animate-pulse"
          style={{ animationDuration: '4s' }}
        />

        {/* Floating Data Nodes */}
        <circle cx="55" cy="58" r="4" fill="#00E5FF" className="animate-ping" style={{ animationDuration: '3.2s' }} />
        <circle cx="185" cy="58" r="4" fill="#0055FF" className="animate-ping" style={{ animationDuration: '2.8s' }} />
        <circle cx="120" cy="206" r="3.5" fill="#FF263F" className="animate-pulse" />
      </svg>

      {/* 2. Interactive 3D Mascot ("SM-Sentinel") in center */}
      <div className="relative z-10">
        <CyberMascot
          state={isScanning ? 'scanning' : 'idle'}
          size={180}
          className="hover:scale-105 transition-transform"
        />
      </div>

      {/* 3. Floating Magnifying Scanning Lens Widget */}
      <div
        className="absolute -bottom-2 -right-2 z-20 hidden sm:flex items-center justify-center p-2 rounded-2xl bg-white/10 dark:bg-black/40 backdrop-blur-md border border-[#00E5FF]/40 shadow-lg animate-bounce"
        style={{ animationDuration: '4s' }}
      >
        <svg viewBox="0 0 40 40" fill="none" className="w-8 h-8">
          <circle cx="18" cy="18" r="11" stroke="#00E5FF" strokeWidth="2.5" />
          <line x1="26" y1="26" x2="35" y2="35" stroke="#00E5FF" strokeWidth="3" strokeLinecap="round" />
          <circle cx="18" cy="18" r="4" fill="#FF263F" className="animate-ping" style={{ animationDuration: '2s' }} />
        </svg>
      </div>
    </div>
  );
}
