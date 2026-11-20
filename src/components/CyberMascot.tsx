import { useState } from 'react';

export type MascotState = 'idle' | 'scanning' | 'threat' | 'success';

interface CyberMascotProps {
  state?: MascotState;
  size?: number;
  className?: string;
  onClick?: () => void;
  interactive?: boolean;
}

/**
 * 3D-Styled Cyber Guardian Mascot ("SM-Sentinel")
 * Completely transparent background, WhatsApp-sticker style fluid looping animation.
 * Adapts to Dark and Light modes automatically.
 */
export function CyberMascot({
  state = 'idle',
  size = 140,
  className = '',
  onClick,
  interactive = true,
}: CyberMascotProps) {
  const [isHovered, setIsHovered] = useState(false);

  // Determine active visual tone
  const isThreat = state === 'threat';
  const isScanning = state === 'scanning';
  const isSuccess = state === 'success';

  // Primary accent colors
  const primaryGlow = isThreat
    ? '#FF263F'
    : isSuccess
      ? '#10B981'
      : '#0055FF';

  const secondaryGlow = isThreat
    ? '#FF5C70'
    : isSuccess
      ? '#34D399'
      : '#00E5FF';

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => interactive && setIsHovered(true)}
      onMouseLeave={() => interactive && setIsHovered(false)}
      style={{ width: size, height: size }}
      className={`relative inline-flex items-center justify-center select-none transition-transform duration-300 ${
        interactive ? 'cursor-pointer hover:scale-105 active:scale-95' : ''
      } ${className}`}
      aria-label={`SM-Sentinel Cyber Guardian (${state})`}
      role="img"
    >
      <svg
        viewBox="0 0 200 200"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full overflow-visible drop-shadow-[0_10px_20px_rgba(0,85,255,0.15)] dark:drop-shadow-[0_10px_25px_rgba(0,85,255,0.25)]"
      >
        <defs>
          {/* Gradients */}
          <linearGradient id="robotBodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#1E293B" className="dark:stop-[#1E2230]" />
            <stop offset="50%" stopColor="#0F172A" className="dark:stop-[#0B0D14]" />
            <stop offset="100%" stopColor="#020617" className="dark:stop-[#030408]" />
          </linearGradient>

          <linearGradient id="robotArmorLight" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#475569" className="dark:stop-[#2E3547]" />
            <stop offset="100%" stopColor="#1E293B" className="dark:stop-[#11141E]" />
          </linearGradient>

          <linearGradient id="shieldPlateGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={primaryGlow} stopOpacity="0.8" />
            <stop offset="100%" stopColor={secondaryGlow} stopOpacity="0.2" />
          </linearGradient>

          <filter id="cyberGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Floating Animation Group */}
        <g
          className="animate-mascot-float"
          style={{
            animation: isScanning
              ? 'mascotBob 1.6s ease-in-out infinite'
              : 'mascotBob 3.2s ease-in-out infinite',
            transformOrigin: '100px 100px',
          }}
        >
          {/* Subtle Outer Energy Orbit Ring */}
          <ellipse
            cx="100"
            cy="165"
            rx="50"
            ry="12"
            fill="none"
            stroke={primaryGlow}
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="opacity-40 animate-spin"
            style={{ animationDuration: isScanning ? '4s' : '10s', transformOrigin: '100px 165px' }}
          />

          {/* Holographic Ground Reflection/Shadow */}
          <ellipse
            cx="100"
            cy="172"
            rx="38"
            ry="8"
            fill={primaryGlow}
            className="opacity-20 blur-[6px] animate-pulse"
          />

          {/* Floating Torso */}
          <g>
            <path
              d="M72 116 L128 116 L120 148 L80 148 Z"
              fill="url(#robotBodyGrad)"
              stroke="url(#robotArmorLight)"
              strokeWidth="2"
            />
            {/* Chest Energy Core (Reactor) */}
            <circle
              cx="100"
              cy="132"
              r="8"
              fill={primaryGlow}
              filter="url(#cyberGlow)"
              className="animate-pulse"
            />
            <circle
              cx="100"
              cy="132"
              r="12"
              fill="none"
              stroke={secondaryGlow}
              strokeWidth="1.2"
              strokeDasharray="3 2"
              className="animate-spin"
              style={{ animationDuration: isScanning ? '2s' : '6s', transformOrigin: '100px 132px' }}
            />
          </g>

          {/* Floating Shoulders & Cyber Arms */}
          <g>
            {/* Left Arm / Shield Hand */}
            <path
              d="M66 122 Q52 130 58 144 Q66 142 70 130 Z"
              fill="url(#robotBodyGrad)"
              stroke={primaryGlow}
              strokeWidth="1.2"
              className="transition-transform duration-300"
            />
            {/* Right Arm */}
            <path
              d="M134 122 Q148 130 142 144 Q134 142 130 130 Z"
              fill="url(#robotBodyGrad)"
              stroke={primaryGlow}
              strokeWidth="1.2"
              className="transition-transform duration-300"
            />
          </g>

          {/* Robotic Head */}
          <g transform={isHovered ? 'translate(0, -2)' : 'translate(0, 0)'}>
            {/* Dual Antenna Beacons */}
            <line x1="72" y1="62" x2="62" y2="44" stroke={secondaryGlow} strokeWidth="2.5" strokeLinecap="round" />
            <circle cx="62" cy="44" r="3" fill={primaryGlow} className="animate-ping" style={{ animationDuration: '2s' }} />

            <line x1="128" y1="62" x2="138" y2="44" stroke={secondaryGlow} strokeWidth="2.5" strokeLinecap="round" />
            <circle cx="138" cy="44" r="3" fill={primaryGlow} className="animate-ping" style={{ animationDuration: '2.5s' }} />

            {/* Helmet Outer Shell */}
            <rect
              x="64"
              y="58"
              width="72"
              height="54"
              rx="18"
              fill="url(#robotBodyGrad)"
              stroke="url(#robotArmorLight)"
              strokeWidth="2.5"
            />

            {/* Helmet Forehead Crown / Sensor Accent */}
            <path
              d="M86 58 L114 58 L108 65 L92 65 Z"
              fill={primaryGlow}
              className="opacity-80"
            />

            {/* Digital Visor Display Screen */}
            <rect
              x="72"
              y="68"
              width="56"
              height="30"
              rx="10"
              fill="#000000"
              stroke={secondaryGlow}
              strokeWidth="1.5"
            />

            {/* Visor Content Based on State */}
            {isThreat ? (
              // Threat Stance: Alert Red Eyes + Warning Icon
              <g>
                <path
                  d="M82 78 L94 88 M94 78 L82 88"
                  stroke="#FF263F"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  className="animate-pulse"
                />
                <path
                  d="M106 78 L118 88 M118 78 L106 88"
                  stroke="#FF263F"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  className="animate-pulse"
                />
              </g>
            ) : isScanning ? (
              // Scanning Stance: Active Laser Beam Sweeping
              <g>
                <circle cx="86" cy="83" r="4.5" fill={primaryGlow} filter="url(#cyberGlow)" />
                <circle cx="114" cy="83" r="4.5" fill={primaryGlow} filter="url(#cyberGlow)" />
                <rect
                  x="74"
                  y="81"
                  width="52"
                  height="3"
                  fill={secondaryGlow}
                  className="animate-pulse"
                  opacity="0.8"
                />
              </g>
            ) : isSuccess ? (
              // Success Stance: Happy Chevron Eyes + Green Glow
              <g>
                <path
                  d="M82 86 L87 81 L92 86"
                  fill="none"
                  stroke="#10B981"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M108 86 L113 81 L118 86"
                  fill="none"
                  stroke="#10B981"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </g>
            ) : (
              // Idle Stance: Friendly Bright Cyan Eyes with Gentle Blink
              <g>
                <ellipse cx="86" cy="83" rx="5" ry="6" fill="#00E5FF" filter="url(#cyberGlow)">
                  <animate
                    attributeName="ry"
                    values="6;6;0.5;6;6"
                    dur="3.8s"
                    repeatCount="indefinite"
                  />
                </ellipse>
                <ellipse cx="114" cy="83" rx="5" ry="6" fill="#00E5FF" filter="url(#cyberGlow)">
                  <animate
                    attributeName="ry"
                    values="6;6;0.5;6;6"
                    dur="3.8s"
                    repeatCount="indefinite"
                  />
                </ellipse>
              </g>
            )}

            {/* Ear Audio Sensors */}
            <rect x="58" y="74" width="6" height="18" rx="2" fill={primaryGlow} opacity="0.8" />
            <rect x="136" y="74" width="6" height="18" rx="2" fill={primaryGlow} opacity="0.8" />
          </g>

          {/* Micro Orbiting Security Nodes */}
          <circle cx="48" cy="98" r="2.5" fill={secondaryGlow} className="animate-ping" style={{ animationDuration: '3s' }} />
          <circle cx="154" cy="112" r="2" fill={primaryGlow} className="animate-ping" style={{ animationDuration: '2.4s' }} />
        </g>
      </svg>
    </div>
  );
}
