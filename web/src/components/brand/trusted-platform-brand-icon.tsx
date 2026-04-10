interface TrustedPlatformBrandIconProps {
  className?: string;
}

export function TrustedPlatformBrandIcon({
  className = "h-8 w-8",
}: TrustedPlatformBrandIconProps) {
  return (
    <svg className={className} viewBox="0 0 320 320" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="tpBrandPanel" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#0f172a" />
          <stop offset="55%" stopColor="#334155" />
          <stop offset="100%" stopColor="#111827" />
        </linearGradient>
        <linearGradient id="tpBrandFrame" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#64748b" />
          <stop offset="100%" stopColor="#60a5fa" />
        </linearGradient>
        <linearGradient id="tpBrandShield" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#e2f0ff" />
          <stop offset="100%" stopColor="#c7ddff" />
        </linearGradient>
        <linearGradient id="tpBrandCore" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#b9dbff" />
          <stop offset="100%" stopColor="#60a5fa" />
        </linearGradient>
        <linearGradient id="tpBrandPulse" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#dbeafe" stopOpacity="0.08" />
          <stop offset="50%" stopColor="#dbeafe" stopOpacity="0.56" />
          <stop offset="100%" stopColor="#dbeafe" stopOpacity="0.08" />
        </linearGradient>
        <filter id="tpBrandShadow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="14" stdDeviation="12" floodColor="#0f172a" floodOpacity="0.22" />
        </filter>
      </defs>

      <rect x="24" y="24" width="272" height="272" rx="52" fill="#f5f8fc" />
      <g filter="url(#tpBrandShadow)">
        <rect x="48" y="48" width="224" height="224" rx="52" fill="url(#tpBrandPanel)" />
        <rect x="84" y="84" width="152" height="152" rx="36" fill="url(#tpBrandFrame)" opacity="0.15" />
        <rect x="96" y="96" width="128" height="128" rx="30" fill="#162235" />
        <rect x="108" y="108" width="104" height="104" rx="24" fill="none" stroke="#bfdbfe" strokeOpacity="0.22" strokeWidth="4" />
        <path d="M94 132h18M94 160h18M94 188h18M208 132h18M208 160h18M208 188h18" stroke="url(#tpBrandPulse)" strokeWidth="6" strokeLinecap="round" />
        <path d="M132 94v18M160 94v18M188 94v18M132 208v18M160 208v18M188 208v18" stroke="url(#tpBrandPulse)" strokeWidth="6" strokeLinecap="round" />
        <path
          d="M160 116
             l34 14
             v28
             c0 29-13 49-34 58
             c-21-9-34-29-34-58
             v-28
             z"
          fill="url(#tpBrandShield)"
        />
        <path
          d="M160 126
             l24 10
             v21
             c0 18-8 32-24 40
             c-16-8-24-22-24-40
             v-21
             z"
          fill="none"
          stroke="#5b6c85"
          strokeOpacity="0.36"
          strokeWidth="3"
        />
        <g fill="url(#tpBrandCore)">
          <rect x="138" y="141" width="18" height="18" rx="5" />
          <rect x="164" y="141" width="18" height="18" rx="5" />
          <rect x="138" y="167" width="18" height="18" rx="5" />
          <rect x="164" y="167" width="18" height="18" rx="5" />
        </g>
        <path d="M156 150h8M147 159v8M173 159v8M156 176h8" stroke="#eff6ff" strokeWidth="4" strokeLinecap="round" />
      </g>
    </svg>
  );
}
