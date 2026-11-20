import React, { useState } from 'react';

export type StickerType =
  | 'shield'
  | 'radar'
  | 'scanner'
  | 'lock'
  | 'warning'
  | 'threat'
  | 'link'
  | 'network'
  | 'success'
  | 'robot'
  | 'search_3d'
  | 'error_401'
  | 'error_403'
  | 'error_404'
  | 'error_429'
  | 'error_500'
  | 'error_502'
  | 'error_503'
  | 'disconnected_plugs'
  | 'dns_globe'
  | 'source_code'
  | 'subdomain_tree'
  | 'vault_shield'
  | 'policy_book';

interface StickerProps {
  type: StickerType;
  size?: number;
  className?: string;
  interactive?: boolean;
  onClick?: () => void;
}

/**
 * Interactive 3D-Style Animated Cyber Stickers (WhatsApp Sticker Aesthetic)
 * 100% transparent backgrounds, GPU-composited motion, prefers-reduced-motion compliant.
 */
export function CyberSticker({
  type,
  size = 56,
  className = '',
  interactive = true,
  onClick,
}: StickerProps) {
  const [pulseBoost, setPulseBoost] = useState(false);

  const handleClick = () => {
    if (interactive) {
      setPulseBoost(true);
      setTimeout(() => setPulseBoost(false), 650);
    }
    onClick?.();
  };

  const containerClasses = `relative inline-flex items-center justify-center select-none transition-transform duration-300 will-change-transform ${
    interactive
      ? 'cursor-pointer hover:scale-110 active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] rounded-2xl'
      : ''
  } ${pulseBoost ? 'scale-110' : ''} ${className}`;

  switch (type) {
    case 'search_3d':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Animated Search Sticker"
        >
          <svg
            viewBox="0 0 140 140"
            fill="none"
            className="h-full w-full drop-shadow-[0_12px_24px_rgba(255,38,63,0.28)]"
          >
            <defs>
              <radialGradient id="searchCoreHalo" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#FF263F" stopOpacity="0.35" />
                <stop offset="55%" stopColor="#0055FF" stopOpacity="0.16" />
                <stop offset="100%" stopColor="#000000" stopOpacity="0" />
              </radialGradient>
              <linearGradient id="lensRimGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#FFFFFF" />
                <stop offset="45%" stopColor="#FF263F" />
                <stop offset="100%" stopColor="#00E5FF" />
              </linearGradient>
              <linearGradient id="lensGlassGrad" x1="15%" y1="15%" x2="85%" y2="85%">
                <stop offset="0%" stopColor="#1E293B" stopOpacity="0.92" />
                <stop offset="50%" stopColor="#0B132B" stopOpacity="0.88" />
                <stop offset="100%" stopColor="#020617" stopOpacity="0.96" />
              </linearGradient>
              <linearGradient id="handleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#FF263F" />
                <stop offset="100%" stopColor="#991B1B" />
              </linearGradient>
            </defs>

            {/* Holographic Depth Glow */}
            <circle cx="70" cy="70" r="64" fill="url(#searchCoreHalo)" />

            {/* Outer Orbital Particle Track */}
            <g className="motion-reduce:animate-none animate-spin" style={{ animationDuration: '12s', transformOrigin: '70px 70px' }}>
              <circle
                cx="70"
                cy="70"
                r="54"
                stroke="#FF263F"
                strokeWidth="1.2"
                strokeDasharray="6 10"
                strokeOpacity="0.45"
              />
              <circle cx="124" cy="70" r="3.5" fill="#FF263F" />
              <circle cx="16" cy="70" r="2.5" fill="#00E5FF" />
            </g>

            {/* Counter-Rotating Light Path Ring */}
            <g
              className="motion-reduce:animate-none"
              style={{ transformOrigin: '70px 70px', animation: 'spin 9s linear infinite reverse' }}
            >
              <circle
                cx="70"
                cy="70"
                r="42"
                stroke="#00E5FF"
                strokeWidth="1"
                strokeDasharray="12 16"
                strokeOpacity="0.4"
              />
              <circle cx="70" cy="28" r="2.5" fill="#FFFFFF" />
            </g>

            {/* Floating 3D Magnifier Group */}
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; 0,-4; 0,0"
                dur="3.4s"
                repeatCount="indefinite"
              />
              {/* 3D Shadow Plate */}
              <ellipse cx="64" cy="112" rx="26" ry="5" fill="#FF263F" fillOpacity="0.2" />

              {/* Magnifier Handle */}
              <path
                d="M84 82 L109 107 C113 111 113 117 109 120 C105 123 99 123 95 119 L72 95 Z"
                fill="url(#handleGrad)"
                stroke="#FFFFFF"
                strokeOpacity="0.35"
                strokeWidth="1.5"
              />
              <line x1="89" y1="89" x2="104" y2="104" stroke="#FFFFFF" strokeOpacity="0.45" strokeWidth="2" strokeLinecap="round" />

              {/* Outer 3D Beveled Lens Frame */}
              <circle cx="62" cy="60" r="30" fill="url(#lensGlassGrad)" stroke="url(#lensRimGrad)" strokeWidth="4.5" />
              <circle cx="62" cy="60" r="24" stroke="#00E5FF" strokeOpacity="0.25" strokeWidth="1" />

              {/* Sweeping Digital Light Beam inside Lens */}
              <path
                d="M42 60 H82"
                stroke="#00E5FF"
                strokeWidth="2"
                strokeLinecap="round"
                strokeOpacity="0.85"
              >
                <animateTransform
                  attributeName="transform"
                  type="translate"
                  values="0,-14; 0,14; 0,-14"
                  dur="2.4s"
                  repeatCount="indefinite"
                />
              </path>

              {/* Specular Glass Shine */}
              <path
                d="M44 46 C48 39 58 37 68 39"
                stroke="#FFFFFF"
                strokeOpacity="0.65"
                strokeWidth="3"
                strokeLinecap="round"
              />
              {/* Floating Digital Particle Nodes */}
              <circle cx="53" cy="57" r="2.2" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
              <circle cx="71" cy="64" r="2.2" fill="#FF263F" className="animate-pulse motion-reduce:animate-none" />
              <circle cx="62" cy="50" r="1.8" fill="#FFFFFF" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '2.2s' }} />
            </g>
          </svg>
        </div>
      );

    case 'error_401':
    case 'error_403':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Restricted Access 3D Sticker"
        >
          <svg viewBox="0 0 140 140" fill="none" className="h-full w-full drop-shadow-[0_10px_22px_rgba(255,38,63,0.4)]">
            <defs>
              <linearGradient id="shieldErrGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#1E293B" />
                <stop offset="100%" stopColor="#090D16" />
              </linearGradient>
              <linearGradient id="crimsonLockGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#FF263F" />
                <stop offset="100%" stopColor="#991B1B" />
              </linearGradient>
            </defs>
            <circle
              cx="70"
              cy="70"
              r="58"
              stroke={type === 'error_401' ? '#F59E0B' : '#FF263F'}
              strokeWidth="1.5"
              strokeDasharray="8 8"
              strokeOpacity="0.55"
              className="animate-spin motion-reduce:animate-none"
              style={{ animationDuration: '11s', transformOrigin: '70px 70px' }}
            />
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; 0,-4; 0,0"
                dur="3s"
                repeatCount="indefinite"
              />
              <path
                d="M70 22 L106 36 C106 68 92 94 70 108 C48 94 34 68 34 36 Z"
                fill="url(#shieldErrGrad)"
                stroke={type === 'error_401' ? '#F59E0B' : '#FF263F'}
                strokeWidth="3"
              />
              <path
                d="M57 58 V49 C57 42 63 37 70 37 C77 37 83 42 83 49 V58"
                stroke="#FFFFFF"
                strokeWidth="4"
                strokeLinecap="round"
              />
              <rect x="50" y="57" width="40" height="28" rx="7" fill="url(#crimsonLockGrad)" stroke="#FFFFFF" strokeOpacity="0.4" strokeWidth="1.5" />
              <circle cx="70" cy="69" r="4" fill="#FFFFFF" className="animate-pulse motion-reduce:animate-none" />
              <path d="M68 72 H72 L73 79 H67 Z" fill="#FFFFFF" />
            </g>
          </svg>
        </div>
      );

    case 'error_404':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Broken Link 404 3D Sticker"
        >
          <svg viewBox="0 0 140 140" fill="none" className="h-full w-full drop-shadow-[0_10px_22px_rgba(0,229,255,0.3)]">
            <defs>
              <linearGradient id="brokenA" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#00E5FF" />
                <stop offset="100%" stopColor="#0055FF" />
              </linearGradient>
              <linearGradient id="brokenB" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#FF263F" />
                <stop offset="100%" stopColor="#991B1B" />
              </linearGradient>
            </defs>
            <circle
              cx="70"
              cy="70"
              r="56"
              stroke="#00E5FF"
              strokeOpacity="0.25"
              strokeWidth="1.5"
              strokeDasharray="6 10"
              className="animate-spin motion-reduce:animate-none"
              style={{ animationDuration: '14s', transformOrigin: '70px 70px' }}
            />
            {/* Left Floating Chain Link */}
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; -3,-3; 0,0"
                dur="2.8s"
                repeatCount="indefinite"
              />
              <rect
                x="26"
                y="62"
                width="38"
                height="24"
                rx="12"
                transform="rotate(-30 45 74)"
                fill="#0B132B"
                stroke="url(#brokenA)"
                strokeWidth="4.5"
              />
            </g>
            {/* Right Floating Chain Link */}
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; 3,3; 0,0"
                dur="2.8s"
                repeatCount="indefinite"
              />
              <rect
                x="76"
                y="54"
                width="38"
                height="24"
                rx="12"
                transform="rotate(-30 95 66)"
                fill="#1F0B10"
                stroke="url(#brokenB)"
                strokeWidth="4.5"
              />
            </g>
            {/* Electric Spark Gap */}
            <path
              d="M64 56 L70 46 M70 94 L76 84 M58 70 L82 70"
              stroke="#FFFFFF"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeDasharray="3 4"
              className="animate-pulse motion-reduce:animate-none"
            />
            <circle cx="70" cy="70" r="5" fill="#FF263F" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '2s' }} />
          </svg>
        </div>
      );

    case 'error_429':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Rate Limit 429 3D Sticker"
        >
          <svg viewBox="0 0 140 140" fill="none" className="h-full w-full drop-shadow-[0_10px_22px_rgba(245,158,11,0.38)]">
            <circle cx="70" cy="70" r="54" stroke="#F59E0B" strokeOpacity="0.3" strokeWidth="2" />
            <circle
              cx="70"
              cy="70"
              r="46"
              stroke="#F59E0B"
              strokeWidth="4"
              strokeDasharray="190 95"
              strokeLinecap="round"
              className="animate-spin motion-reduce:animate-none"
              style={{ animationDuration: '6s', transformOrigin: '70px 70px' }}
            />
            <circle cx="70" cy="70" r="34" fill="#18120B" stroke="#F59E0B" strokeOpacity="0.6" strokeWidth="2" />
            <path d="M70 46 V70 L86 80" stroke="#FFFFFF" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="70" cy="70" r="5" fill="#FF263F" />
          </svg>
        </div>
      );

    case 'error_500':
    case 'error_502':
    case 'error_503':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Service Error 3D Sticker"
        >
          <svg viewBox="0 0 140 140" fill="none" className="h-full w-full drop-shadow-[0_10px_22px_rgba(255,38,63,0.45)]">
            <circle
              cx="70"
              cy="70"
              r="56"
              stroke="#FF263F"
              strokeOpacity="0.35"
              strokeWidth="1.5"
              strokeDasharray="5 7"
              className="animate-spin motion-reduce:animate-none"
              style={{ animationDuration: '10s', transformOrigin: '70px 70px' }}
            />
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; 0,-3; 0,0"
                dur="2.8s"
                repeatCount="indefinite"
              />
              {/* 3D Server Blades */}
              <rect x="34" y="34" width="72" height="22" rx="6" fill="#0F172A" stroke="#00E5FF" strokeWidth="2" />
              <circle cx="46" cy="45" r="3" fill="#10B981" />
              <line x1="56" y1="45" x2="94" y2="45" stroke="#334155" strokeWidth="3" strokeLinecap="round" />

              <rect x="34" y="62" width="72" height="22" rx="6" fill="#1F0B10" stroke="#FF263F" strokeWidth="2.5" />
              <circle cx="46" cy="73" r="3.5" fill="#FF263F" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '1.6s' }} />
              <line x1="56" y1="73" x2="94" y2="73" stroke="#FF263F" strokeOpacity="0.55" strokeWidth="3" strokeLinecap="round" />

              <rect x="34" y="90" width="72" height="22" rx="6" fill="#0F172A" stroke="#F59E0B" strokeWidth="2" />
              <circle cx="46" cy="101" r="3" fill="#F59E0B" className="animate-pulse motion-reduce:animate-none" />
              <line x1="56" y1="101" x2="94" y2="101" stroke="#334155" strokeWidth="3" strokeLinecap="round" />
            </g>
          </svg>
        </div>
      );

    case 'disconnected_plugs':
      return (
        <div
          style={{ width: size, height: size }}
          className={containerClasses}
          onClick={handleClick}
          role={interactive ? 'button' : undefined}
          tabIndex={interactive ? 0 : undefined}
          aria-label="Disconnected Plugs Cut Wire Animated Sticker"
        >
          <svg
            viewBox="0 0 160 160"
            fill="none"
            className="h-full w-full drop-shadow-[0_14px_26px_rgba(255,38,63,0.34)]"
          >
            <defs>
              <radialGradient id="plugCutHalo" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#FF263F" stopOpacity="0.32" />
                <stop offset="55%" stopColor="#00E5FF" stopOpacity="0.14" />
                <stop offset="100%" stopColor="#000000" stopOpacity="0" />
              </radialGradient>
              <linearGradient id="plugBodyLeft" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#1E293B" />
                <stop offset="100%" stopColor="#090D16" />
              </linearGradient>
              <linearGradient id="plugBodyRight" x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#1F0B10" />
                <stop offset="100%" stopColor="#0F172A" />
              </linearGradient>
              <linearGradient id="copperProng" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#F59E0B" />
                <stop offset="100%" stopColor="#FDE68A" />
              </linearGradient>
              <linearGradient id="cableGradA" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#0055FF" />
                <stop offset="100%" stopColor="#00E5FF" />
              </linearGradient>
              <linearGradient id="cableGradB" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#FF263F" />
                <stop offset="100%" stopColor="#991B1B" />
              </linearGradient>
            </defs>

            {/* Holographic Halo & Broken Orbital Ring */}
            <circle cx="80" cy="80" r="70" fill="url(#plugCutHalo)" />
            <circle
              cx="80"
              cy="80"
              r="64"
              stroke="#FF263F"
              strokeOpacity="0.35"
              strokeWidth="1.5"
              strokeDasharray="10 8"
              className="animate-spin motion-reduce:animate-none"
              style={{ animationDuration: '14s', transformOrigin: '80px 80px' }}
            />

            {/* LEFT PLUG + CABLE HALF (recoils gently left as wire snaps) */}
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; -5,-2; -7,1; -2,-1; 0,0"
                keyTimes="0; 0.3; 0.55; 0.8; 1"
                dur="2.4s"
                repeatCount="indefinite"
              />
              {/* Cable running from Left Plug into center cut point */}
              <path
                d="M46 80 C56 80 61 76 70 81"
                stroke="url(#cableGradA)"
                strokeWidth="7"
                strokeLinecap="round"
              />
              <path
                d="M46 80 C56 80 61 76 70 81"
                stroke="#FFFFFF"
                strokeOpacity="0.45"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
              {/* Frayed Copper Core Filaments at Left Cut End */}
              <path d="M70 79 L76 75 M70 81 L77 81 M70 83 L75 87" stroke="#F59E0B" strokeWidth="2" strokeLinecap="round" />

              {/* Left Plug Strain Relief & 3D Body */}
              <rect x="38" y="72" width="10" height="16" rx="3" fill="#00E5FF" fillOpacity="0.85" />
              <rect
                x="18"
                y="62"
                width="24"
                height="36"
                rx="7"
                fill="url(#plugBodyLeft)"
                stroke="#00E5FF"
                strokeWidth="2.5"
              />
              <line x1="25" y1="71" x2="25" y2="89" stroke="#334155" strokeWidth="2.5" strokeLinecap="round" />
              <line x1="31" y1="71" x2="31" y2="89" stroke="#334155" strokeWidth="2.5" strokeLinecap="round" />
              {/* Left Metallic Prongs */}
              <rect x="8" y="69" width="11" height="6" rx="2" fill="url(#copperProng)" />
              <rect x="8" y="85" width="11" height="6" rx="2" fill="url(#copperProng)" />
              <circle cx="30" cy="69" r="2.2" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
            </g>

            {/* RIGHT PLUG + CABLE HALF (recoils gently right as wire snaps) */}
            <g>
              <animateTransform
                attributeName="transform"
                type="translate"
                values="0,0; 5,2; 7,-1; 2,1; 0,0"
                keyTimes="0; 0.3; 0.55; 0.8; 1"
                dur="2.4s"
                repeatCount="indefinite"
              />
              {/* Cable running from center cut point into Right Plug */}
              <path
                d="M90 79 C99 84 104 80 114 80"
                stroke="url(#cableGradB)"
                strokeWidth="7"
                strokeLinecap="round"
              />
              <path
                d="M90 79 C99 84 104 80 114 80"
                stroke="#FFFFFF"
                strokeOpacity="0.4"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
              {/* Frayed Copper Core Filaments at Right Cut End */}
              <path d="M90 77 L84 73 M90 79 L83 80 M90 81 L85 86" stroke="#F59E0B" strokeWidth="2" strokeLinecap="round" />

              {/* Right Plug Strain Relief & 3D Body */}
              <rect x="112" y="72" width="10" height="16" rx="3" fill="#FF263F" fillOpacity="0.9" />
              <rect
                x="118"
                y="62"
                width="24"
                height="36"
                rx="7"
                fill="url(#plugBodyRight)"
                stroke="#FF263F"
                strokeWidth="2.5"
              />
              <line x1="129" y1="71" x2="129" y2="89" stroke="#475569" strokeWidth="2.5" strokeLinecap="round" />
              <line x1="135" y1="71" x2="135" y2="89" stroke="#475569" strokeWidth="2.5" strokeLinecap="round" />
              {/* Right Metallic Prongs */}
              <rect x="141" y="69" width="11" height="6" rx="2" fill="url(#copperProng)" />
              <rect x="141" y="85" width="11" height="6" rx="2" fill="url(#copperProng)" />
              <circle cx="130" cy="69" r="2.2" fill="#FF263F" className="animate-pulse motion-reduce:animate-none" />
            </g>

            {/* CENTRAL ANIMATED CUT SLASH & ELECTRIC SPARKS */}
            <g>
              {/* Diagonal Energy Cut Line */}
              <path
                d="M72 52 L88 108"
                stroke="#FFFFFF"
                strokeWidth="2.6"
                strokeLinecap="round"
                strokeDasharray="10 8"
              >
                <animate
                  attributeName="opacity"
                  values="0.15; 1; 0.9; 0.15"
                  dur="2.4s"
                  repeatCount="indefinite"
                />
              </path>
              {/* Electric Sparks Radiating from Snapped Wire */}
              <path
                d="M80 65 L75 56 M80 95 L86 104 M73 72 L65 65 M88 88 L96 95"
                stroke="#FDE047"
                strokeWidth="2.5"
                strokeLinecap="round"
              >
                <animate
                  attributeName="opacity"
                  values="0; 1; 0.2; 1; 0"
                  dur="1.2s"
                  repeatCount="indefinite"
                />
              </path>
              {/* Central Snap Flash Core */}
              <circle cx="80" cy="80" r="6" fill="#FF263F">
                <animate attributeName="r" values="3; 7; 4; 3" dur="1.2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.9; 0.4; 1; 0.9" dur="1.2s" repeatCount="indefinite" />
              </circle>
              <circle cx="80" cy="80" r="2.5" fill="#FFFFFF" />
            </g>
          </svg>
        </div>
      );

    case 'shield':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,85,255,0.4)]">
            <circle
              cx="50"
              cy="50"
              r="44"
              stroke="#0055FF"
              strokeWidth="1.5"
              strokeDasharray="8 6"
              className="animate-spin motion-reduce:animate-none opacity-60"
              style={{ animationDuration: '8s', transformOrigin: '50px 50px' }}
            />
            <path
              d="M50 16 L78 28 C78 54 66 74 50 84 C34 74 22 54 22 28 Z"
              fill="url(#shieldBlueGrad)"
              stroke="#00E5FF"
              strokeWidth="2.5"
            />
            <path
              d="M38 48 L46 56 L64 38"
              fill="none"
              stroke="#FFFFFF"
              strokeWidth="3.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="animate-pulse motion-reduce:animate-none"
            />
            <defs>
              <linearGradient id="shieldBlueGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#0055FF" stopOpacity="0.85" />
                <stop offset="100%" stopColor="#0B132B" stopOpacity="0.95" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      );

    case 'radar':
    case 'scanner':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(255,38,63,0.35)]">
            <circle cx="50" cy="50" r="44" stroke="#FF263F" strokeWidth="1.5" strokeOpacity="0.3" />
            <circle cx="50" cy="50" r="30" stroke="#FF263F" strokeWidth="1.2" strokeDasharray="4 4" strokeOpacity="0.5" />
            <circle cx="50" cy="50" r="16" stroke="#FF263F" strokeWidth="1" strokeOpacity="0.7" />
            <circle cx="50" cy="50" r="5" fill="#FF263F" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '2s' }} />
            <path d="M50 50 L84 26" stroke="#FF263F" strokeWidth="2.5" strokeLinecap="round">
              <animateTransform
                attributeName="transform"
                type="rotate"
                from="0 50 50"
                to="360 50 50"
                dur="2.2s"
                repeatCount="indefinite"
              />
            </path>
            <circle cx="68" cy="36" r="3" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
          </svg>
        </div>
      );

    case 'lock':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,229,255,0.4)]">
            <circle
              cx="50"
              cy="50"
              r="44"
              stroke="#00E5FF"
              strokeWidth="1.5"
              strokeDasharray="6 8"
              className="animate-spin motion-reduce:animate-none opacity-50"
              style={{ animationDuration: '9s', transformOrigin: '50px 50px' }}
            />
            <path
              d="M36 44 V32 C36 24 42 18 50 18 C58 18 64 24 64 32 V44"
              fill="none"
              stroke="#00E5FF"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <rect
              x="28"
              y="44"
              width="44"
              height="36"
              rx="8"
              fill="url(#lockBodyGrad)"
              stroke="#00E5FF"
              strokeWidth="2"
            />
            <circle cx="50" cy="58" r="4.5" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
            <path d="M48 62 L52 62 L53 71 L47 71 Z" fill="#00E5FF" />
            <defs>
              <linearGradient id="lockBodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#1E293B" />
                <stop offset="100%" stopColor="#0B132B" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      );

    case 'warning':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_14px_rgba(245,158,11,0.5)]">
            <path
              d="M50 12 L88 50 L50 88 L12 50 Z"
              fill="url(#warnGrad)"
              stroke="#F59E0B"
              strokeWidth="2.5"
              className="animate-pulse motion-reduce:animate-none"
              style={{ animationDuration: '2.5s' }}
            />
            <line x1="50" y1="34" x2="50" y2="56" stroke="#FFFFFF" strokeWidth="4.5" strokeLinecap="round" />
            <circle cx="50" cy="67" r="3.5" fill="#FFFFFF" />
            <defs>
              <linearGradient id="warnGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#B45309" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#78350F" stopOpacity="0.95" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      );

    case 'threat':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_15px_rgba(255,38,63,0.6)]">
            <polygon
              points="50,14 86,34 86,76 50,96 14,76 14,34"
              fill="url(#threatHexGrad)"
              stroke="#FF263F"
              strokeWidth="2.5"
            />
            <path
              d="M38 42 C38 32 62 32 62 42 C62 49 57 52 57 56 H43 C43 52 38 49 38 42 Z"
              fill="#FFFFFF"
              className="animate-pulse motion-reduce:animate-none"
            />
            <circle cx="44" cy="42" r="3" fill="#FF263F" />
            <circle cx="56" cy="42" r="3" fill="#FF263F" />
            <path d="M44 60 H56 V64 H44 Z" fill="#FFFFFF" />
            <defs>
              <linearGradient id="threatHexGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#7F1D1D" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#450A0A" stopOpacity="0.95" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      );

    case 'link':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,85,255,0.4)]">
            <circle cx="34" cy="66" r="14" stroke="#0055FF" strokeWidth="3" />
            <circle cx="66" cy="34" r="14" stroke="#00E5FF" strokeWidth="3" />
            <line x1="44" y1="56" x2="56" y2="44" stroke="#FFFFFF" strokeWidth="3.5" strokeLinecap="round" />
            <circle cx="50" cy="50" r="3" fill="#00E5FF" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '1.8s' }} />
          </svg>
        </div>
      );

    case 'network':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,229,255,0.4)]">
            <circle cx="50" cy="50" r="9" fill="#0055FF" stroke="#00E5FF" strokeWidth="2" className="animate-pulse motion-reduce:animate-none" />
            <circle cx="24" cy="32" r="6" fill="#00E5FF" />
            <circle cx="76" cy="32" r="6" fill="#00E5FF" />
            <circle cx="76" cy="74" r="6" fill="#00E5FF" />
            <circle cx="24" cy="74" r="6" fill="#00E5FF" />
            <line x1="50" y1="50" x2="24" y2="32" stroke="#0055FF" strokeWidth="1.5" strokeDasharray="3 3" />
            <line x1="50" y1="50" x2="76" y2="32" stroke="#0055FF" strokeWidth="1.5" strokeDasharray="3 3" />
            <line x1="50" y1="50" x2="76" y2="74" stroke="#0055FF" strokeWidth="1.5" strokeDasharray="3 3" />
            <line x1="50" y1="50" x2="24" y2="74" stroke="#0055FF" strokeWidth="1.5" strokeDasharray="3 3" />
          </svg>
        </div>
      );

    case 'success':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_14px_rgba(16,185,129,0.5)]">
            <circle cx="50" cy="50" r="44" stroke="#10B981" strokeWidth="2" strokeDasharray="6 4" className="animate-spin motion-reduce:animate-none" style={{ animationDuration: '10s' }} />
            <circle cx="50" cy="50" r="34" fill="#064E3B" stroke="#10B981" strokeWidth="2.5" />
            <path
              d="M36 50 L46 60 L64 42"
              fill="none"
              stroke="#34D399"
              strokeWidth="4.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      );

    case 'dns_globe':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(255,38,63,0.35)]">
            <circle cx="50" cy="50" r="34" fill="#0B132B" stroke="#00E5FF" strokeWidth="2.2" />
            <ellipse cx="50" cy="50" rx="16" ry="34" stroke="#0055FF" strokeWidth="1.6" />
            <line x1="16" y1="50" x2="84" y2="50" stroke="#0055FF" strokeWidth="1.6" />
            <path d="M22 34 H78 M22 66 H78" stroke="#00E5FF" strokeOpacity="0.45" strokeWidth="1.2" />
            <ellipse
              cx="50"
              cy="50"
              rx="42"
              ry="14"
              transform="rotate(-24 50 50)"
              stroke="#FF263F"
              strokeWidth="2"
              strokeDasharray="6 4"
              className="animate-pulse motion-reduce:animate-none"
            />
            <circle cx="80" cy="36" r="4" fill="#FF263F" />
          </svg>
        </div>
      );

    case 'source_code':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,229,255,0.4)]">
            <rect x="14" y="18" width="72" height="64" rx="10" fill="#0F172A" stroke="#00E5FF" strokeWidth="2.2" />
            <rect x="14" y="18" width="72" height="14" rx="8" fill="#1E293B" />
            <circle cx="24" cy="25" r="2.5" fill="#FF263F" />
            <circle cx="32" cy="25" r="2.5" fill="#F59E0B" />
            <circle cx="40" cy="25" r="2.5" fill="#10B981" />
            <path d="M36 46 L25 56 L36 66" stroke="#00E5FF" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M64 46 L75 56 L64 66" stroke="#FF263F" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
            <line x1="54" y1="43" x2="46" y2="69" stroke="#FFFFFF" strokeWidth="3" strokeLinecap="round" />
            <rect x="18" y="54" width="64" height="2" fill="#FF263F" fillOpacity="0.65" className="animate-pulse motion-reduce:animate-none" />
          </svg>
        </div>
      );

    case 'subdomain_tree':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(255,38,63,0.4)]">
            <rect x="34" y="14" width="32" height="18" rx="5" fill="#111827" stroke="#FF263F" strokeWidth="2.2" />
            <circle cx="50" cy="23" r="3.5" fill="#FF263F" />
            <path d="M50 32 V48 M50 48 H22 V62 M50 48 V62 M50 48 H78 V62" stroke="#00E5FF" strokeWidth="2" strokeLinecap="round" />
            <rect x="12" y="62" width="20" height="16" rx="4" fill="#0F172A" stroke="#10B981" strokeWidth="2" />
            <rect x="40" y="62" width="20" height="16" rx="4" fill="#0F172A" stroke="#00E5FF" strokeWidth="2" />
            <rect x="68" y="62" width="20" height="16" rx="4" fill="#0F172A" stroke="#FF263F" strokeWidth="2" />
            <circle cx="50" cy="48" r="3" fill="#FFFFFF" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '2.2s' }} />
          </svg>
        </div>
      );

    case 'vault_shield':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_14px_rgba(16,185,129,0.4)]">
            <polygon points="50,10 86,28 86,68 50,90 14,68 14,28" fill="#0B132B" stroke="#10B981" strokeWidth="2.5" />
            <circle cx="50" cy="50" r="21" stroke="#00E5FF" strokeWidth="2" strokeDasharray="5 4" className="animate-spin motion-reduce:animate-none" style={{ animationDuration: '12s' }} />
            <rect x="39" y="47" width="22" height="17" rx="4" fill="#1E293B" stroke="#10B981" strokeWidth="2" />
            <path d="M43 47 V41 C43 37 57 37 57 41 V47" stroke="#00E5FF" strokeWidth="2.5" strokeLinecap="round" />
            <circle cx="50" cy="55" r="2.5" fill="#10B981" />
          </svg>
        </div>
      );

    case 'policy_book':
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,85,255,0.4)]">
            <rect x="20" y="16" width="60" height="68" rx="8" fill="#0F172A" stroke="#FF263F" strokeWidth="2.2" />
            <line x1="34" y1="34" x2="68" y2="34" stroke="#00E5FF" strokeWidth="2.5" strokeLinecap="round" />
            <line x1="34" y1="46" x2="64" y2="46" stroke="#94A3B8" strokeWidth="2" strokeLinecap="round" />
            <line x1="34" y1="57" x2="58" y2="57" stroke="#94A3B8" strokeWidth="2" strokeLinecap="round" />
            <path d="M56 67 L62 73 L74 61" stroke="#10B981" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      );

    case 'robot':
    default:
      return (
        <div style={{ width: size, height: size }} className={containerClasses} onClick={handleClick}>
          <svg viewBox="0 0 100 100" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(0,85,255,0.4)]">
            <rect x="22" y="26" width="56" height="44" rx="14" fill="#0F172A" stroke="#00E5FF" strokeWidth="2.5" />
            <rect x="30" y="36" width="40" height="20" rx="6" fill="#000000" stroke="#0055FF" strokeWidth="1.5" />
            <circle cx="40" cy="46" r="3.5" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
            <circle cx="60" cy="46" r="3.5" fill="#00E5FF" className="animate-pulse motion-reduce:animate-none" />
            <line x1="50" y1="26" x2="50" y2="14" stroke="#00E5FF" strokeWidth="2.5" strokeLinecap="round" />
            <circle cx="50" cy="12" r="3" fill="#FF263F" className="animate-ping motion-reduce:animate-none" style={{ animationDuration: '2s' }} />
          </svg>
        </div>
      );
  }
}
