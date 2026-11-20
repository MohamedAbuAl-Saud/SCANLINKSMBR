import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import type { Language } from '../types/scan';
import cyberCommandLabImg from '../assets/images/layered_network_threat_scan_1795127004791.jpg';
import threatRadarMatrixImg from '../assets/images/threat_network_mesh_map_1795127005455.jpg';
import packetOpticsCoreImg from '../assets/images/binary_packet_inspection_1795127004151.jpg';
import domainShieldArchImg from '../assets/images/domain_tls_layers_shield_1795127004611.jpg';
import dnsSubdomainTopologyImg from '../assets/images/dns_routing_layers_topology_1795127005187.jpg';
import sourceCodeForensicsImg from '../assets/images/browser_permission_code_audit_1795127005164.jpg';
import securityVaultArchiveImg from '../assets/images/security_privacy_key_vault_1795127004513.jpg';

function StudioVisualFrame({
  src,
  alt,
  caption,
  aspectClass = 'aspect-video',
}: {
  src: string;
  alt: string;
  caption?: string;
  aspectClass?: string;
}) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return (
      <div
        className={`flex ${aspectClass} w-full flex-col items-center justify-center rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-6 text-center dark:border-[#202020] dark:bg-[#080808]`}
      >
        <ShieldCheck className="h-10 w-10 text-[#FF263F]" aria-hidden="true" />
        <p className="mt-2 text-xs font-medium text-zinc-600 dark:text-zinc-400">{alt}</p>
      </div>
    );
  }

  return (
    <div className="group relative overflow-hidden rounded-xl border border-[#E5E7EB] bg-black dark:border-[#202020]">
      <img
        src={src}
        alt={alt}
        referrerPolicy="no-referrer"
        onError={() => setFailed(true)}
        className={`${aspectClass} w-full object-cover transition-transform duration-500 group-hover:scale-[1.02]`}
      />
      {caption && (
        <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/85 via-black/45 to-transparent px-4 py-3">
          <p className="text-xs font-medium text-white/95">{caption}</p>
        </div>
      )}
    </div>
  );
}

export function HeroTelemetryIllustration({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={cyberCommandLabImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'فحص تهديدات الشبكة متعدد الطبقات لمنصة Scan Link SM'
          : 'Scan Link SM multi-layer network threat inspection topology'
      }
      caption={
        lang === 'ar'
          ? 'فحص تهديد الشبكة كطبقات · جدار SSRF · DNS و TLS · تدقيق أذونات الدخول'
          : 'Layered Network Threat Scan · SSRF Guard · DNS/TLS Layers · Permission Audit'
      }
    />
  );
}

export function ThreatIntelNetworkVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={threatRadarMatrixImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'خريطة الشبكة التفاعلية لمزودي البيانات واستخبارات التهديدات'
          : 'Interactive threat intelligence network mesh and layer interconnections'
      }
      caption={
        lang === 'ar'
          ? 'شبكة ربط مزودي البيانات كطبقات تفاعلية مترابطة مع عزل المفاتيح على الخادم'
          : 'Interactive Provider Network Mesh · Layered Threat Correlation · Server Key Isolation'
      }
    />
  );
}

export function BinaryInspectorVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={packetOpticsCoreImg}
      aspectClass="aspect-[4/3]"
      alt={
        lang === 'ar'
          ? 'فحص التوقيع الثنائي للملفات وحزم البيانات بالذاكرة دون تشغيل'
          : 'In-memory binary magic-byte and packet signature inspection'
      }
      caption={
        lang === 'ar'
          ? 'فحص التوقيع الثنائي وبصمة SHA-256 بالذاكرة فقط · دون تنفيذ أي ملفات'
          : 'In-Memory Magic-Byte & SHA-256 Inspection · Zero Execution Sandbox'
      }
    />
  );
}

export function DomainArchitectureVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={domainShieldArchImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'طبقات الحماية للتحقق من النطاقات الرسمية وسلاسل TLS'
          : 'Domain verification shield and nested TLS defense layers'
      }
      caption={
        lang === 'ar'
          ? 'طبقات التحقق من النطاقات الرسمية وسلاسل TLS · تحليل حتمي متعدد المستويات'
          : 'Official Domain & TLS Layer Shield · Multi-Tier Deterministic Verification'
      }
    />
  );
}

export function SubdomainDnsTopologyVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={dnsSubdomainTopologyImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'خريطة طبقات توجيه DNS والنطاقات الفرعية وسجلات CNAME'
          : 'Layered DNS routing topology and subdomain CNAME delegation map'
      }
      caption={
        lang === 'ar'
          ? 'طبقات توجيه DNS والنطاقات الفرعية وسجلات CNAME وتفويض الاستضافة'
          : 'Layered DNS Routing & Subdomain Topology · A/AAAA/CNAME & Delegation Audit'
      }
    />
  );
}

export function SourceCodeForensicsVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={sourceCodeForensicsImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'تدقيق أذونات المتصفح التلقائية عند الدخول وتحليل سورس JavaScript و DOM'
          : 'Browser entry permission auditing and static HTML/JavaScript code inspection'
      }
      caption={
        lang === 'ar'
          ? 'تدقيق أذونات الدخول (الكاميرا والموقع والإشعارات) ومطابقة الاستخدام المعلن'
          : 'Entry Permission Guard & Static JS Forensics · Stated Usage Verification'
      }
    />
  );
}

export function SecurityVaultVisual({ lang }: { lang: Language }) {
  return (
    <StudioVisualFrame
      src={securityVaultArchiveImg}
      aspectClass="aspect-[16/9]"
      alt={
        lang === 'ar'
          ? 'خزنة عزل الخصوصية والمفاتيح وتخزين السجل المحلي'
          : 'Isolated privacy vault for local browser records and server-only credentials'
      }
      caption={
        lang === 'ar'
          ? 'خزنة الخصوصية المعزولة · سجل محلي بموافقة صريحة وعزل تام لمفاتيح الخادم'
          : 'Zero-Tracking Privacy Vault · Explicit Consent · Backend Key Isolation'
      }
    />
  );
}

export function EmptyHistoryIllustration({ lang = 'en' }: { lang?: Language }) {
  return (
    <div className="mx-auto w-full max-w-[260px]">
      <StudioVisualFrame
        src={securityVaultArchiveImg}
        aspectClass="aspect-[16/9]"
        alt={
          lang === 'ar'
            ? 'خزنة سجل الفحوصات الآمنة المحلية'
            : 'Encrypted local scan history archive vault'
        }
      />
    </div>
  );
}

export function ScanningRadarPulse() {
  return (
    <svg viewBox="0 0 120 120" fill="none" className="h-16 w-16 shrink-0" aria-hidden="true">
      <circle cx="60" cy="60" r="54" className="stroke-zinc-200 dark:stroke-[#222222]" strokeWidth="1.5" />
      <circle cx="60" cy="60" r="38" className="stroke-zinc-300 dark:stroke-[#2A2A2A]" strokeWidth="1.2" strokeDasharray="3 3" />
      <circle cx="60" cy="60" r="20" stroke="#FF263F" strokeOpacity="0.45" strokeWidth="1.5" />
      <path d="M60 60 L98 32" stroke="#FF263F" strokeWidth="2.2" strokeLinecap="round">
        <animateTransform
          attributeName="transform"
          type="rotate"
          from="0 60 60"
          to="360 60 60"
          dur="2.4s"
          repeatCount="indefinite"
        />
      </path>
      <circle cx="60" cy="60" r="5" fill="#FF263F" />
    </svg>
  );
}
