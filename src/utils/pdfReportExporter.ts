import { jsPDF } from 'jspdf';
import type { CheckFinding, Language, RiskClassification, ScanReport } from '../types/scan';
import { OFFICIAL_BRAND_ASSETS } from '../components/BrandMark';
import {
  tAdIntelState,
  tClassification,
  tCookieCategory,
  tFileDownloadCategory,
  tOperationalState,
  tSeverity,
  tStatus,
  tVerdict,
} from '../i18n/translations';
import { safeImageDataUrl } from './sanitize';

const A4_WIDTH_PX = 1240;
const A4_HEIGHT_PX = 1754;
const MARGIN_X = 72;
const CONTENT_WIDTH = A4_WIDTH_PX - MARGIN_X * 2;
const HEADER_SAFE_Y = 72;
const FOOTER_Y = A4_HEIGHT_PX - 70;
const MAX_BODY_Y = FOOTER_Y - 34;
const MAX_PDF_PAGES = 24;

function loadImageElement(src: string): Promise<HTMLImageElement | null> {
  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => resolve(img);
    img.onerror = () => resolve(null);
    img.src = src;
  });
}

function wrapTextLines(
  ctx: CanvasRenderingContext2D,
  text: string,
  maxWidth: number
): string[] {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  if (!clean) return ['—'];
  const words = clean.split(' ');
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (ctx.measureText(candidate).width <= maxWidth) {
      current = candidate;
    } else {
      if (current) lines.push(current);
      if (ctx.measureText(word).width > maxWidth) {
        let slice = '';
        for (const ch of word) {
          if (ctx.measureText(slice + ch).width > maxWidth) {
            if (slice) lines.push(slice);
            slice = ch;
          } else {
            slice += ch;
          }
        }
        current = slice;
      } else {
        current = word;
      }
    }
  }
  if (current) lines.push(current);
  return lines.length > 0 ? lines : ['—'];
}

function classificationColor(cls: RiskClassification): string {
  switch (cls) {
    case 'CRITICAL':
      return '#DC2626';
    case 'HIGH':
      return '#FF263F';
    case 'MEDIUM':
      return '#D97706';
    case 'LOW':
      return '#CA8A04';
    case 'OFFICIAL_DOMAIN_VERIFIED':
      return '#0284C7';
    case 'UNKNOWN':
      return '#52525B';
    default:
      return '#16A34A';
  }
}

class WhitePageComposer {
  private pages: { canvas: HTMLCanvasElement; hasContent: boolean }[] = [];
  private canvas!: HTMLCanvasElement;
  private ctx!: CanvasRenderingContext2D;
  private y = HEADER_SAFE_Y;
  private pageLimitReached = false;
  private readonly isRtl: boolean;
  private readonly lang: Language;
  private readonly report: ScanReport;
  private readonly logoImg: HTMLImageElement | null;
  private readonly faviconImg: HTMLImageElement | null;
  private readonly fontSans: string;
  private readonly fontMono = '"JetBrains Mono", ui-monospace, SFMono-Regular, monospace';

  constructor(
    report: ScanReport,
    lang: Language,
    logoImg: HTMLImageElement | null,
    faviconImg: HTMLImageElement | null
  ) {
    this.report = report;
    this.lang = lang;
    this.isRtl = lang === 'ar';
    this.logoImg = logoImg;
    this.faviconImg = faviconImg;
    this.fontSans = this.isRtl
      ? '"IBM Plex Sans Arabic", "Plus Jakarta Sans", system-ui, sans-serif'
      : '"Plus Jakarta Sans", "Manrope", system-ui, sans-serif';
    this.newPage();
  }

  public isFull(): boolean {
    return this.pageLimitReached;
  }

  public newPage(): boolean {
    if (this.pages.length >= MAX_PDF_PAGES) {
      this.pageLimitReached = true;
      return false;
    }

    // Re-use last page if nothing was drawn on it yet (prevents blank/unused pages)
    const lastPage = this.pages[this.pages.length - 1];
    if (lastPage && !lastPage.hasContent) {
      this.canvas = lastPage.canvas;
      this.ctx = lastPage.canvas.getContext('2d')!;
      this.y = HEADER_SAFE_Y;
      return true;
    }

    const c = document.createElement('canvas');
    c.width = A4_WIDTH_PX;
    c.height = A4_HEIGHT_PX;
    const ctx = c.getContext('2d');
    if (!ctx) throw new Error('Canvas 2D context unavailable for PDF generation');

    // Pure white A4 sheet
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, A4_WIDTH_PX, A4_HEIGHT_PX);

    // Subtle top red precision accent line on every page
    ctx.fillStyle = '#FF263F';
    ctx.fillRect(MARGIN_X, 40, CONTENT_WIDTH, 3);

    this.canvas = c;
    this.ctx = ctx;
    this.pages.push({ canvas: c, hasContent: false });
    this.y = HEADER_SAFE_Y;
    return true;
  }

  private markPageHasContent(): void {
    const cur = this.pages[this.pages.length - 1];
    if (cur) cur.hasContent = true;
  }

  private ensureSpace(neededHeight: number): boolean {
    if (this.pageLimitReached) return false;
    if (this.y + neededHeight > MAX_BODY_Y) {
      if (!this.newPage()) {
        return false;
      }
      this.drawContinuationHeader();
    }
    this.markPageHasContent();
    return true;
  }

  private drawContinuationHeader(): void {
    const ctx = this.ctx;
    ctx.save();
    ctx.textBaseline = 'top';
    ctx.font = `600 17px ${this.fontSans}`;
    ctx.fillStyle = '#52525B';
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const xText = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;
    const title =
      this.lang === 'ar'
        ? `تقرير Scan Link SM — تابع (${this.report.scanId.slice(0, 8)})`
        : `Scan Link SM Security Intelligence Report — Cont. (${this.report.scanId.slice(0, 8)})`;
    ctx.fillText(title, xText, this.y);
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X, this.y + 26, CONTENT_WIDTH, 1);
    ctx.restore();
    this.y += 44;
    this.markPageHasContent();
  }

  private drawStamp(x: number, y: number): void {
    const ctx = this.ctx;
    const w = 264;
    const h = 92;
    ctx.save();
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#FFF5F6';
    ctx.fillRect(x, y, w, h);

    ctx.strokeStyle = '#FF263F';
    ctx.lineWidth = 2.2;
    ctx.strokeRect(x, y, w, h);

    ctx.strokeStyle = '#FF263F';
    ctx.lineWidth = 0.9;
    ctx.strokeRect(x + 5, y + 5, w - 10, h - 10);

    ctx.textAlign = 'center';
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.fillStyle = '#FF263F';
    ctx.font = `800 15px ${this.fontSans}`;
    ctx.fillText(
      this.isRtl ? 'تقرير موثّق · Scan Link SM' : 'SCAN LINK SM VERIFIED',
      x + w / 2,
      y + 32
    );

    ctx.direction = 'ltr';
    ctx.fillStyle = '#111827';
    ctx.font = `700 13px ${this.fontMono}`;
    ctx.fillText(`ID: ${this.report.scanId.slice(0, 12)}`, x + w / 2, y + 55);

    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.fillStyle = '#52525B';
    ctx.font = `600 11px ${this.fontSans}`;
    ctx.fillText(
      this.isRtl ? 'تحليل حتمي بدون ذكاء اصطناعي' : 'DETERMINISTIC ENGINE STAMP',
      x + w / 2,
      y + 76
    );
    ctx.restore();
  }

  public drawCoverHeader(): void {
    const ctx = this.ctx;
    const headerTop = this.y; // 72
    const headerBandHeight = 96;

    // 1. Top Header Band: Official Logo (never colliding with stamp or title)
    if (this.logoImg && this.logoImg.naturalWidth > 0) {
      const targetH = 74;
      const aspect = this.logoImg.naturalWidth / Math.max(1, this.logoImg.naturalHeight);
      const targetW = Math.min(280, targetH * aspect);
      const logoX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - targetW : MARGIN_X;
      const logoY = headerTop + Math.round((headerBandHeight - targetH) / 2);
      ctx.drawImage(this.logoImg, logoX, logoY, targetW, targetH);
    } else {
      ctx.save();
      ctx.textBaseline = 'top';
      ctx.font = `800 30px ${this.fontSans}`;
      ctx.fillStyle = '#111827';
      ctx.direction = 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      ctx.fillText('Scan Link SM', this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X, headerTop + 26);
      ctx.restore();
    }

    // 2. Opposite side verification stamp inside the dedicated 96px top band
    const stampX = this.isRtl ? MARGIN_X : A4_WIDTH_PX - MARGIN_X - 264;
    this.drawStamp(stampX, headerTop + 2);

    // 3. Dedicated Separator Rule Below Header Band
    const ruleY = headerTop + headerBandHeight + 18;
    ctx.save();
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X, ruleY, CONTENT_WIDTH, 1.5);
    ctx.restore();

    // 4. Title & Scan Metadata safely below separator
    this.y = ruleY + 28;

    ctx.save();
    ctx.textBaseline = 'top';
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const xAnchor = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;

    ctx.fillStyle = '#111827';
    ctx.font = `800 30px ${this.fontSans}`;
    const mainTitle =
      this.lang === 'ar'
        ? 'تقرير الاستخبارات الأمنية للمواقع والروابط'
        : 'Website & URL Threat Intelligence Report';
    const titleLines = wrapTextLines(ctx, mainTitle, CONTENT_WIDTH);
    for (const ln of titleLines) {
      ctx.fillText(ln, xAnchor, this.y);
      this.y += 40;
    }

    this.y += 4;
    ctx.fillStyle = '#4B5563';
    ctx.font = `500 16px ${this.fontSans}`;
    const formattedDate = new Date(this.report.completedAt)
      .toISOString()
      .replace('T', ' ')
      .slice(0, 19);
    const metaText =
      this.lang === 'ar'
        ? `معرّف الفحص: ${this.report.scanId.slice(0, 14)}   ·   التوقيت: ${formattedDate} UTC   ·   المدة: ${(this.report.durationMs / 1000).toFixed(2)} ث`
        : `Scan ID: ${this.report.scanId}   |   ${formattedDate} UTC   |   Duration: ${(this.report.durationMs / 1000).toFixed(2)}s`;
    ctx.fillText(metaText, xAnchor, this.y);
    ctx.restore();

    this.y += 38;
    this.markPageHasContent();
  }

  public drawExecutiveSummary(): void {
    const ctx = this.ctx;
    const verdictColor = classificationColor(this.report.classification);
    const cov =
      this.report.inspectionCoveragePercent ??
      Math.round(
        (this.report.summaryStats.availableProviders /
          Math.max(1, this.report.summaryStats.totalProviders)) *
          100
      );

    ctx.save();
    ctx.font = `500 17px ${this.fontSans}`;
    const recLines = wrapTextLines(
      ctx,
      this.report.recommendation?.[this.lang] || '',
      CONTENT_WIDTH - 48
    ).slice(0, 3);

    ctx.font = `500 15px ${this.fontMono}`;
    const subPrefix = this.lang === 'ar' ? 'الرابط المُدخَل: ' : 'Submitted: ';
    const finPrefix = this.lang === 'ar' ? 'الوجهة النهائية: ' : 'Final URL: ';
    const subLines = wrapTextLines(ctx, `${subPrefix}${this.report.submittedUrl}`, CONTENT_WIDTH - 48).slice(0, 2);
    const finLines = wrapTextLines(ctx, `${finPrefix}${this.report.finalDestinationUrl}`, CONTENT_WIDTH - 48).slice(0, 2);
    ctx.restore();

    const boxH = 146 + (subLines.length + finLines.length) * 22 + recLines.length * 24 + 20;
    if (!this.ensureSpace(boxH + 18)) return;

    const top = this.y;
    ctx.save();
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#F9FAFB';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.fillRect(MARGIN_X, top, CONTENT_WIDTH, boxH);
    ctx.strokeRect(MARGIN_X, top, CONTENT_WIDTH, boxH);

    // Top color bar inside summary card
    ctx.fillStyle = verdictColor;
    ctx.fillRect(MARGIN_X, top, CONTENT_WIDTH, 6);

    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const xPad = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 24 : MARGIN_X + 24;

    let cy = top + 22;
    ctx.fillStyle = verdictColor;
    ctx.font = `800 25px ${this.fontSans}`;
    ctx.fillText(tClassification(this.report.classification, this.lang), xPad, cy);
    cy += 34;

    ctx.fillStyle = '#111827';
    ctx.font = `700 19px ${this.fontSans}`;
    ctx.fillText(
      `${this.lang === 'ar' ? 'الحكم النهائي:' : 'Final Verdict:'} ${tVerdict(this.report.verdict, this.lang)}`,
      xPad,
      cy
    );
    cy += 30;

    ctx.fillStyle = '#374151';
    ctx.font = `600 16px ${this.fontSans}`;
    ctx.fillText(
      `${this.lang === 'ar' ? 'درجة المخاطر' : 'Risk Score'}: ${this.report.riskScore}/100   ·   ${this.lang === 'ar' ? 'الموثوقية' : 'Confidence'}: ${this.report.confidenceScore}% (${this.report.confidenceLabel})   ·   ${this.lang === 'ar' ? 'التغطية' : 'Coverage'}: ${cov}%`,
      xPad,
      cy
    );
    cy += 32;

    // URLs with circular site icon badge
    ctx.fillStyle = '#4B5563';
    ctx.font = `500 14.5px ${this.fontMono}`;
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';

    const badgeR = 12;
    const badgeX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 24 - badgeR : MARGIN_X + 24 + badgeR;
    const badgeY = cy + 22;

    ctx.save();
    ctx.beginPath();
    ctx.arc(badgeX, badgeY, badgeR, 0, Math.PI * 2);
    ctx.closePath();
    ctx.clip();
    if (this.faviconImg && this.faviconImg.naturalWidth > 0) {
      ctx.drawImage(this.faviconImg, badgeX - badgeR, badgeY - badgeR, badgeR * 2, badgeR * 2);
    } else {
      ctx.fillStyle = '#FF263F';
      ctx.fillRect(badgeX - badgeR, badgeY - badgeR, badgeR * 2, badgeR * 2);
      ctx.fillStyle = '#FFFFFF';
      ctx.font = `800 11px ${this.fontSans}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const domainInitial = (this.report.finalDestinationUrl || this.report.submittedUrl || 'S').replace(/^https?:\/\//, '')[0].toUpperCase();
      ctx.fillText(domainInitial, badgeX, badgeY);
    }
    ctx.restore();

    const textOffset = this.isRtl ? xPad - badgeR * 2 - 14 : xPad + badgeR * 2 + 14;
    for (const ln of subLines) {
      ctx.fillText(ln, textOffset, cy);
      cy += 22;
    }
    for (const ln of finLines) {
      ctx.fillText(ln, textOffset, cy);
      cy += 22;
    }
    cy += 8;

    // Recommendation
    ctx.fillStyle = '#111827';
    ctx.font = `500 16px ${this.fontSans}`;
    for (const ln of recLines) {
      ctx.fillText(ln, xPad, cy);
      cy += 24;
    }

    ctx.restore();
    this.y = top + boxH + 22;
    this.markPageHasContent();
  }

  public drawClassificationLevelDiagram(): void {
    const boxH = 290;
    if (!this.ensureSpace(boxH + 24)) return;

    const top = this.y;
    const ctx = this.ctx;
    const score = Math.max(0, Math.min(100, this.report.riskScore));
    const accent = classificationColor(this.report.classification);

    ctx.save();
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.fillRect(MARGIN_X, top, CONTENT_WIDTH, boxH);
    ctx.strokeRect(MARGIN_X, top, CONTENT_WIDTH, boxH);

    // Header strip
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const titleX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 24 : MARGIN_X + 24;
    ctx.fillStyle = '#111827';
    ctx.font = `800 19px ${this.fontSans}`;
    ctx.fillText(
      this.lang === 'ar'
        ? 'رسم مستوى التصنيف ومؤشر درجة الخطورة (0 – 100)'
        : 'Risk Classification Level Diagram & Score Gauge (0 – 100)',
      titleX,
      top + 16
    );

    const gaugeX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 140 : MARGIN_X + 140;
    const gaugeY = top + 135;
    const radius = 64;

    // Gauge track
    ctx.beginPath();
    ctx.arc(gaugeX, gaugeY, radius, 0, Math.PI * 2);
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 14;
    ctx.stroke();

    // Active risk arc
    const startAngle = -Math.PI / 2;
    const arcSweep = Math.max(0.06, (score / 100) * Math.PI * 2);
    ctx.beginPath();
    ctx.arc(gaugeX, gaugeY, radius, startAngle, startAngle + arcSweep);
    ctx.strokeStyle = accent;
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Score numeral in center
    ctx.direction = 'ltr';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = accent;
    ctx.font = `800 32px ${this.fontMono}`;
    ctx.fillText(`${score}`, gaugeX, gaugeY - 8);
    ctx.fillStyle = '#6B7280';
    ctx.font = `600 14px ${this.fontMono}`;
    ctx.fillText('/ 100', gaugeX, gaugeY + 18);

    // Tier classification ladder
    const tiers: {
      cls: RiskClassification;
      range: string;
      color: string;
      label: string;
    }[] = [
      {
        cls: 'OFFICIAL_DOMAIN_VERIFIED',
        range: 'VERIFIED',
        color: '#0284C7',
        label: this.lang === 'ar' ? 'نطاق رسمي موثّق' : 'Official Verified',
      },
      {
        cls: 'NO_KNOWN_THREATS',
        range: '0 – 15',
        color: '#16A34A',
        label: this.lang === 'ar' ? 'لا توجد تهديدات' : 'No Known Threats',
      },
      {
        cls: 'LOW',
        range: '16 – 50',
        color: '#CA8A04',
        label: this.lang === 'ar' ? 'خطورة منخفضة' : 'Low Risk',
      },
      {
        cls: 'MEDIUM',
        range: '51 – 67',
        color: '#D97706',
        label: this.lang === 'ar' ? 'متوسطة (>50)' : 'Medium Risk (>50)',
      },
      {
        cls: 'HIGH',
        range: '68 – 81',
        color: '#FF263F',
        label: this.lang === 'ar' ? 'خطورة مرتفعة' : 'High Risk',
      },
      {
        cls: 'CRITICAL',
        range: '82 – 100',
        color: '#DC2626',
        label: this.lang === 'ar' ? 'خطورة حرجة' : 'Critical Risk',
      },
    ];

    const ladderStartX = this.isRtl ? MARGIN_X + 24 : MARGIN_X + 280;
    const ladderWidth = CONTENT_WIDTH - 304;
    const cols = 3;
    const cellW = (ladderWidth - 20) / cols;
    const cellH = 52;

    tiers.forEach((tier, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const cx = ladderStartX + col * (cellW + 10);
      const cy = top + 62 + row * (cellH + 10);
      const active =
        this.report.classification === tier.cls ||
        (tier.cls === 'NO_KNOWN_THREATS' &&
          (this.report.classification === 'SAFE_INDICATORS' ||
            this.report.classification === 'INFORMATIONAL'));

      ctx.fillStyle = active ? `${tier.color}18` : '#F9FAFB';
      ctx.strokeStyle = active ? tier.color : '#E5E7EB';
      ctx.lineWidth = active ? 2.4 : 1;
      ctx.fillRect(cx, cy, cellW, cellH);
      ctx.strokeRect(cx, cy, cellW, cellH);

      // Accent color stripe
      ctx.fillStyle = tier.color;
      ctx.fillRect(this.isRtl ? cx + cellW - 5 : cx, cy, 5, cellH);

      ctx.textBaseline = 'top';
      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const tx = this.isRtl ? cx + cellW - 14 : cx + 14;
      ctx.fillStyle = active ? tier.color : '#111827';
      ctx.font = `${active ? 800 : 700} 13.5px ${this.fontSans}`;
      ctx.fillText(tier.label, tx, cy + 8);

      ctx.direction = 'ltr';
      ctx.fillStyle = '#6B7280';
      ctx.font = `600 11.5px ${this.fontMono}`;
      ctx.fillText(tier.range, tx, cy + 29);
    });

    // Bottom Horizontal Risk Ruler
    const barX = MARGIN_X + 28;
    const barY = top + 236;
    const barW = CONTENT_WIDTH - 56;
    const barH = 15;

    const segments = [
      { from: 0, to: 15, color: '#16A34A' },
      { from: 15, to: 50, color: '#EAB308' },
      { from: 50, to: 68, color: '#F59E0B' },
      { from: 68, to: 82, color: '#FF263F' },
      { from: 82, to: 100, color: '#DC2626' },
    ];
    for (const seg of segments) {
      const sx = barX + (seg.from / 100) * barW;
      const sw = ((seg.to - seg.from) / 100) * barW;
      ctx.fillStyle = seg.color;
      ctx.fillRect(sx, barY, sw, barH);
    }

    // Threshold tick marks
    ctx.textBaseline = 'top';
    ctx.direction = 'ltr';
    ctx.textAlign = 'center';
    ctx.font = `600 11.5px ${this.fontMono}`;
    for (const mark of [0, 15, 50, 68, 82, 100]) {
      const mx = barX + (mark / 100) * barW;
      ctx.fillStyle = '#374151';
      ctx.fillRect(mx - 1, barY - 4, 2, barH + 8);
      ctx.fillText(`${mark}`, mx, barY + barH + 6);
    }

    // Score pointer triangle
    const ptrX = barX + (score / 100) * barW;
    ctx.fillStyle = '#111827';
    ctx.beginPath();
    ctx.moveTo(ptrX, barY - 2);
    ctx.lineTo(ptrX - 7, barY - 13);
    ctx.lineTo(ptrX + 7, barY - 13);
    ctx.closePath();
    ctx.fill();

    ctx.restore();
    this.y = top + boxH + 22;
    this.markPageHasContent();
  }

  public drawAnalyticsCharts(): void {
    const boxH = 370;
    if (!this.ensureSpace(boxH + 22)) return;

    const top = this.y;
    const ctx = this.ctx;
    const stats = this.report.summaryStats;
    const total = Math.max(1, stats.passedChecks + stats.warningChecks + stats.failedChecks + stats.incompleteChecks);

    const statusSlices = [
      { label: this.lang === 'ar' ? 'سليم' : 'Passed', value: stats.passedChecks, color: '#16A34A' },
      { label: this.lang === 'ar' ? 'تحذير' : 'Warning', value: stats.warningChecks, color: '#F59E0B' },
      { label: this.lang === 'ar' ? 'فشل' : 'Failed', value: stats.failedChecks, color: '#EF233C' },
      { label: this.lang === 'ar' ? 'غير مكتمل' : 'Unknown', value: stats.incompleteChecks, color: '#71717A' },
    ];

    ctx.save();
    ctx.textBaseline = 'top';
    const gap = 20;
    const leftW = Math.floor((CONTENT_WIDTH - gap) * 0.43);
    const rightW = CONTENT_WIDTH - gap - leftW;
    const leftX = this.isRtl ? MARGIN_X + rightW + gap : MARGIN_X;
    const rightX = this.isRtl ? MARGIN_X : MARGIN_X + leftW + gap;

    // --- Left Panel: Status Distribution Donut Chart ---
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.fillRect(leftX, top, leftW, boxH);
    ctx.strokeRect(leftX, top, leftW, boxH);

    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    ctx.fillStyle = '#111827';
    ctx.font = `800 18px ${this.fontSans}`;
    ctx.fillText(
      this.lang === 'ar' ? 'الرسم البياني لتوزيع نتائج الفحص' : 'Checks Distribution Chart',
      this.isRtl ? leftX + leftW - 20 : leftX + 20,
      top + 16
    );

    const dCx = leftX + leftW / 2;
    const dCy = top + 140;
    const dRadius = 70;
    let angle = -Math.PI / 2;

    const nonZero = statusSlices.filter((s) => s.value > 0);
    if (nonZero.length === 0) {
      ctx.beginPath();
      ctx.arc(dCx, dCy, dRadius, 0, Math.PI * 2);
      ctx.strokeStyle = '#E5E7EB';
      ctx.lineWidth = 22;
      ctx.stroke();
    } else {
      for (const slice of nonZero) {
        const sweep = (slice.value / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(dCx, dCy, dRadius, angle, angle + sweep);
        ctx.strokeStyle = slice.color;
        ctx.lineWidth = 22;
        ctx.stroke();
        angle += sweep;
      }
    }

    // Center total count
    ctx.direction = 'ltr';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#111827';
    ctx.font = `800 25px ${this.fontMono}`;
    ctx.fillText(`${stats.totalChecks}`, dCx, dCy - 6);
    ctx.fillStyle = '#6B7280';
    ctx.font = `600 12px ${this.fontSans}`;
    ctx.fillText(this.lang === 'ar' ? 'فحص' : 'CHECKS', dCx, dCy + 16);

    // Legend 2x2 grid below donut
    ctx.textBaseline = 'top';
    statusSlices.forEach((s, idx) => {
      const col = idx % 2;
      const row = Math.floor(idx / 2);
      const colW = (leftW - 44) / 2;
      const lx = leftX + 22 + col * colW;
      const ly = top + 246 + row * 52;
      const pct = Math.round((s.value / total) * 100);

      const boxX = this.isRtl ? lx + colW - 14 : lx;
      ctx.fillStyle = s.color;
      ctx.fillRect(boxX, ly + 4, 12, 12);

      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const labelPos = this.isRtl ? boxX - 8 : lx + 20;
      ctx.fillStyle = '#374151';
      ctx.font = `700 13.5px ${this.fontSans}`;
      ctx.fillText(`${s.label}`, labelPos, ly);
      ctx.direction = 'ltr';
      ctx.fillStyle = '#6B7280';
      ctx.font = `600 12.5px ${this.fontMono}`;
      ctx.fillText(`${s.value} (${pct}%)`, labelPos, ly + 20);
    });

    // --- Right Panel: Section-by-Section Bar Chart ---
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.fillRect(rightX, top, rightW, boxH);
    ctx.strokeRect(rightX, top, rightW, boxH);

    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    ctx.fillStyle = '#111827';
    ctx.font = `800 18px ${this.fontSans}`;
    ctx.fillText(
      this.lang === 'ar' ? 'الرسم البياني للمحاور الأمنية' : 'Security Sections Health Chart',
      this.isRtl ? rightX + rightW - 20 : rightX + 20,
      top + 16
    );

    const topSections = [...this.report.sections]
      .sort((a, b) => {
        const aF = this.report.findings.filter((f) => f.section === a.id && f.status === 'failed').length;
        const bF = this.report.findings.filter((f) => f.section === b.id && f.status === 'failed').length;
        return bF - aF;
      })
      .slice(0, 7);

    let ry = top + 56;
    const barTotalW = rightW - 44;
    for (const sec of topSections) {
      const secFindings = this.report.findings.filter((f) => f.section === sec.id);
      const secTotal = Math.max(1, secFindings.length);
      const passed = secFindings.filter((f) => f.status === 'pass').length;
      const warned = secFindings.filter((f) => f.status === 'warning').length;
      const failed = secFindings.filter((f) => f.status === 'failed').length;
      const unknown = Math.max(0, secFindings.length - passed - warned - failed);

      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      ctx.fillStyle = '#1F2937';
      ctx.font = `700 13px ${this.fontSans}`;
      const label = wrapTextLines(ctx, sec.title[this.lang], barTotalW - 105)[0];
      ctx.fillText(label, this.isRtl ? rightX + rightW - 22 : rightX + 22, ry);

      ctx.textAlign = this.isRtl ? 'left' : 'right';
      ctx.fillStyle = sec.status === 'failed' ? '#EF233C' : sec.status === 'warning' ? '#D97706' : '#16A34A';
      ctx.font = `700 12px ${this.fontSans}`;
      ctx.fillText(tStatus(sec.status, this.lang), this.isRtl ? rightX + 22 : rightX + rightW - 22, ry);

      const barTop = ry + 19;
      ctx.fillStyle = '#F3F4F6';
      ctx.fillRect(rightX + 22, barTop, barTotalW, 11);

      let bx = rightX + 22;
      const segs = [
        { count: passed, color: '#16A34A' },
        { count: warned, color: '#F59E0B' },
        { count: failed, color: '#EF233C' },
        { count: unknown, color: '#9CA3AF' },
      ];
      for (const seg of segs) {
        if (seg.count > 0) {
          const w = (seg.count / secTotal) * barTotalW;
          ctx.fillStyle = seg.color;
          ctx.fillRect(bx, barTop, w, 11);
          bx += w;
        }
      }
      ry += 42;
    }

    ctx.restore();
    this.y = top + boxH + 22;
    this.markPageHasContent();
  }

  public drawSectionTitle(title: string): boolean {
    if (!this.ensureSpace(60)) return false;
    const ctx = this.ctx;
    ctx.save();
    ctx.textBaseline = 'top';
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const x = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;
    ctx.fillStyle = '#111827';
    ctx.font = `800 21px ${this.fontSans}`;
    ctx.fillText(title, x, this.y);
    ctx.fillStyle = '#FF263F';
    ctx.fillRect(this.isRtl ? A4_WIDTH_PX - MARGIN_X - 68 : MARGIN_X, this.y + 28, 68, 3);
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X, this.y + 31, CONTENT_WIDTH, 1.2);
    ctx.restore();
    this.y += 44;
    this.markPageHasContent();
    return true;
  }

  public drawKeyValueBlock(rows: { label: string; value: string; accent?: string }[]): void {
    const ctx = this.ctx;
    for (const row of rows) {
      if (this.pageLimitReached) return;
      ctx.font = `500 16px ${this.fontSans}`;
      const valLines = wrapTextLines(ctx, row.value, CONTENT_WIDTH - 28);
      const needed = 28 + valLines.length * 22 + 12;
      if (!this.ensureSpace(needed)) return;

      ctx.save();
      ctx.textBaseline = 'top';
      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const x = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;

      ctx.fillStyle = row.accent || '#374151';
      ctx.font = `700 16px ${this.fontSans}`;
      ctx.fillText(row.label, x, this.y);
      this.y += 24;

      ctx.fillStyle = '#111827';
      ctx.font = `500 15.5px ${this.fontSans}`;
      for (const ln of valLines) {
        ctx.fillText(ln, x, this.y);
        this.y += 22;
      }
      ctx.restore();
      this.y += 8;
    }
    this.y += 6;
    this.markPageHasContent();
  }

  public drawBulletList(items: string[], bulletColor = '#FF263F'): void {
    const ctx = this.ctx;
    for (const item of items) {
      if (this.pageLimitReached) return;
      ctx.font = `500 16px ${this.fontSans}`;
      const lines = wrapTextLines(ctx, item, CONTENT_WIDTH - 32);
      const needed = lines.length * 22 + 8;
      if (!this.ensureSpace(needed)) return;

      ctx.save();
      ctx.textBaseline = 'top';
      ctx.fillStyle = bulletColor;
      const dotX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 7 : MARGIN_X + 7;
      ctx.beginPath();
      ctx.arc(dotX, this.y + 10, 3.8, 0, Math.PI * 2);
      ctx.fill();

      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const textX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 24 : MARGIN_X + 24;
      ctx.fillStyle = '#1F2937';
      ctx.font = `500 15.5px ${this.fontSans}`;
      for (const ln of lines) {
        ctx.fillText(ln, textX, this.y);
        this.y += 22;
      }
      ctx.restore();
      this.y += 6;
    }
    this.y += 6;
    this.markPageHasContent();
  }

  public drawScreenshotBlock(img: HTMLImageElement | null): void {
    if (!img || !img.naturalWidth || this.pageLimitReached) return;
    const maxW = CONTENT_WIDTH;
    const maxH = 340;
    const aspect = img.naturalWidth / Math.max(1, img.naturalHeight);
    let drawW = maxW;
    let drawH = drawW / aspect;
    if (drawH > maxH) {
      drawH = maxH;
      drawW = drawH * aspect;
    }
    if (!this.ensureSpace(drawH + 30)) return;

    const x = MARGIN_X + Math.round((CONTENT_WIDTH - drawW) / 2);
    const ctx = this.ctx;
    ctx.save();
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.drawImage(img, x, this.y, drawW, drawH);
    ctx.strokeRect(x, this.y, drawW, drawH);
    ctx.restore();
    this.y += drawH + 22;
    this.markPageHasContent();
  }

  /**
   * Structured Finding Box & Frame Card (Organized with neat borders and zero text overlap)
   */
  public drawFindingCard(f: CheckFinding): boolean {
    const ctx = this.ctx;
    const isAr = this.isRtl;
    const lang = this.lang;

    let statusColor = '#16A34A';
    let statusBg = '#F0FDF4';
    let statusBorder = '#BBF7D0';
    if (f.status === 'failed') {
      statusColor = '#DC2626';
      statusBg = '#FEF2F2';
      statusBorder = '#FECACA';
    } else if (f.status === 'warning') {
      statusColor = '#D97706';
      statusBg = '#FFFBEB';
      statusBorder = '#FDE68A';
    } else if (f.status === 'unknown') {
      statusColor = '#52525B';
      statusBg = '#F4F4F5';
      statusBorder = '#E4E4E7';
    }

    const cardW = CONTENT_WIDTH;
    const paddingX = 22;
    const textW = cardW - paddingX * 2 - 12;

    ctx.save();
    ctx.font = `600 15px ${this.fontSans}`;
    const resultLines = wrapTextLines(ctx, `${isAr ? 'النتيجة: ' : 'Result: '}${f.result[lang]}`, textW);

    ctx.font = `500 14px ${this.fontSans}`;
    const expLines = wrapTextLines(ctx, `${isAr ? 'التحليل والتفسير: ' : 'Analysis: '}${f.explanation[lang]}`, textW);

    ctx.font = `500 12.5px ${this.fontMono}`;
    const evidenceLines = wrapTextLines(ctx, `${isAr ? 'الدليل: ' : 'Evidence: '}${f.evidence}`, textW - 20);

    let recLines: string[] = [];
    if (f.recommendedAction && f.recommendedAction[lang]) {
      ctx.font = `500 13px ${this.fontSans}`;
      recLines = wrapTextLines(ctx, `${isAr ? 'الإجراء الموصى به: ' : 'Guidance: '}${f.recommendedAction[lang]}`, textW);
    }
    ctx.restore();

    const headerH = 40;
    const resultH = resultLines.length * 22 + 6;
    const expH = expLines.length * 20 + 8;
    const evidenceH = evidenceLines.length * 18 + 18;
    const recH = recLines.length > 0 ? recLines.length * 19 + 8 : 0;
    const cardH = headerH + resultH + expH + evidenceH + recH + 16;

    if (!this.ensureSpace(cardH + 16)) return false;

    const top = this.y;
    ctx.save();

    // 1. Card container background & border
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.4;
    ctx.fillRect(MARGIN_X, top, cardW, cardH);
    ctx.strokeRect(MARGIN_X, top, cardW, cardH);

    // 2. Colored left/right accent bar
    ctx.fillStyle = statusColor;
    const accentX = isAr ? MARGIN_X + cardW - 6 : MARGIN_X;
    ctx.fillRect(accentX, top, 6, cardH);

    // 3. Header: Title and Status Badge
    let cy = top + 14;
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';

    const contentStartX = isAr ? MARGIN_X + cardW - paddingX - 10 : MARGIN_X + paddingX + 10;

    // Test Title
    ctx.fillStyle = '#111827';
    ctx.font = `800 16px ${this.fontSans}`;
    const testTitle = f.test[lang];
    ctx.fillText(testTitle, contentStartX, cy);

    // Status Badge
    const badgeText = `${tStatus(f.status, lang).toUpperCase()} · ${tSeverity(f.severity, lang).toUpperCase()}`;
    ctx.font = `700 12px ${this.fontSans}`;
    const badgeW = ctx.measureText(badgeText).width + 16;
    const badgeH = 22;
    const badgeX = isAr ? MARGIN_X + paddingX : MARGIN_X + cardW - paddingX - badgeW;
    const badgeY = cy - 2;

    ctx.fillStyle = statusBg;
    ctx.strokeStyle = statusBorder;
    ctx.lineWidth = 1;
    ctx.fillRect(badgeX, badgeY, badgeW, badgeH);
    ctx.strokeRect(badgeX, badgeY, badgeW, badgeH);

    ctx.direction = 'ltr';
    ctx.textAlign = 'center';
    ctx.fillStyle = statusColor;
    ctx.fillText(badgeText, badgeX + badgeW / 2, badgeY + 4);

    // Divider line
    cy += 30;
    ctx.fillStyle = '#F3F4F6';
    ctx.fillRect(MARGIN_X + 10, cy, cardW - 20, 1.2);
    cy += 10;

    // 4. Result Line(s)
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';
    ctx.font = `600 14.5px ${this.fontSans}`;
    ctx.fillStyle = f.status === 'failed' ? '#B91C1C' : f.status === 'warning' ? '#B45309' : '#15803D';
    for (const ln of resultLines) {
      ctx.fillText(ln, contentStartX, cy);
      cy += 22;
    }
    cy += 4;

    // 5. Explanation Line(s)
    ctx.font = `500 13.5px ${this.fontSans}`;
    ctx.fillStyle = '#374151';
    for (const ln of expLines) {
      ctx.fillText(ln, contentStartX, cy);
      cy += 20;
    }
    cy += 4;

    // 6. Evidence Box (code style)
    const evBoxX = isAr ? MARGIN_X + paddingX : MARGIN_X + paddingX + 8;
    const evBoxW = cardW - paddingX * 2 - 8;
    const evBoxH = evidenceLines.length * 18 + 12;

    ctx.fillStyle = '#F8FAFC';
    ctx.strokeStyle = '#E2E8F0';
    ctx.lineWidth = 1;
    ctx.fillRect(evBoxX, cy, evBoxW, evBoxH);
    ctx.strokeRect(evBoxX, cy, evBoxW, evBoxH);

    ctx.font = `500 12px ${this.fontMono}`;
    ctx.fillStyle = '#475569';
    let evY = cy + 6;
    const evTextX = isAr ? evBoxX + evBoxW - 10 : evBoxX + 10;
    for (const ln of evidenceLines) {
      ctx.fillText(ln, evTextX, evY);
      evY += 18;
    }
    cy += evBoxH + 6;

    // 7. Recommended action (if present)
    if (recLines.length > 0) {
      ctx.font = `500 13px ${this.fontSans}`;
      ctx.fillStyle = '#1E293B';
      for (const ln of recLines) {
        ctx.fillText(ln, contentStartX, cy);
        cy += 19;
      }
      cy += 4;
    }

    ctx.restore();
    this.y = top + cardH + 16;
    this.markPageHasContent();
    return true;
  }

  /**
   * Section 7: Redirect Chain, DNS & SSL/TLS Telemetry in structured boxes and frames.
   * Prevents text collision and ensures clean, professional framing.
   */
  public drawNetworkAndTlsSection(): boolean {
    const isAr = this.isRtl;
    const ctx = this.ctx;
    const report = this.report;

    if (
      !this.drawSectionTitle(
        isAr
          ? '٧. سلسلة إعادة التوجيه وDNS وشهادة التشفير'
          : '7. Redirect Chain, DNS & SSL/TLS Certificate Telemetry'
      )
    ) {
      return false;
    }

    const cardW = CONTENT_WIDTH;
    const paddingX = 20;
    const textW = cardW - paddingX * 2 - 10;

    // --- Box 1: Redirect Chain Hops ---
    const redirects = report.redirects || [];
    let redirectLines: string[] = [];
    if (redirects.length > 0) {
      redirectLines = redirects.map((h) =>
        isAr
          ? `قفزة #${h.step} [${h.redirectType || 'HTTP'} · كود ${h.statusCode ?? '200'}] -> ${h.url} (${h.latencyMs}ms${h.downgradedToHttp ? ' · خفض أمني إلى HTTP!' : ''})`
          : `Hop #${h.step} [${h.redirectType || 'HTTP'} · Code ${h.statusCode ?? '200'}] -> ${h.url} (${h.latencyMs}ms${h.downgradedToHttp ? ' · Security Downgrade to HTTP!' : ''})`
      );
    } else {
      redirectLines = [
        isAr
          ? 'اتصال مباشر بالنطاق الهدف دون قفزات إعادة توجيه وسيطة (0 قفزات · استجابة سريعة)'
          : 'Direct connection to target domain without intermediary redirect hops (0 Hops · Fast direct response)',
      ];
    }

    ctx.save();
    ctx.font = `500 13px ${this.fontSans}`;
    const allRedirectWrapped: string[] = [];
    for (const rLine of redirectLines) {
      allRedirectWrapped.push(...wrapTextLines(ctx, rLine, textW));
    }
    ctx.restore();

    const box1H = 46 + allRedirectWrapped.length * 20 + 12;
    if (this.ensureSpace(box1H + 14)) {
      const curY = this.y;
      ctx.save();
      ctx.fillStyle = '#FFFFFF';
      ctx.strokeStyle = '#E2E8F0';
      ctx.lineWidth = 1.3;
      ctx.fillRect(MARGIN_X, curY, cardW, box1H);
      ctx.strokeRect(MARGIN_X, curY, cardW, box1H);

      ctx.fillStyle = redirects.some((r) => r.downgradedToHttp) ? '#DC2626' : '#0284C7';
      ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, box1H);

      ctx.textBaseline = 'top';
      ctx.direction = isAr ? 'rtl' : 'ltr';
      ctx.textAlign = isAr ? 'right' : 'left';
      const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

      ctx.fillStyle = '#0F172A';
      ctx.font = `800 15px ${this.fontSans}`;
      ctx.fillText(
        isAr ? 'مسار قفزات إعادة التوجيه والتحويلات الشبكية (Redirect Chain Telemetry)' : 'Network Redirect Chain & Latency Hops',
        textStartX,
        curY + 12
      );

      ctx.fillStyle = '#F1F5F9';
      ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

      let textY = curY + 44;
      ctx.font = `500 12.5px ${this.fontMono}`;
      ctx.fillStyle = '#1E293B';
      for (const ln of allRedirectWrapped) {
        ctx.fillText(ln, textStartX, textY);
        textY += 20;
      }
      ctx.restore();
      this.y = curY + box1H + 14;
      this.markPageHasContent();
    }

    // --- Box 2: Domain & DNS Records ---
    if (report.domainIntel) {
      const di = report.domainIntel;
      const dnsItems: { label: string; val: string }[] = [
        {
          label: isAr ? 'النطاق المسجّل والعمر' : 'Registrable Domain & Age',
          val: isAr
            ? `${di.registrableDomain} (العمر الإرشادي: ${di.domainAgeDays ?? 'غير متوفر'} يوماً)`
            : `${di.registrableDomain} (Age: ${di.domainAgeDays ?? 'Unknown'} days)`,
        },
        {
          label: isAr ? 'عنوان IP والخادم المستضيف' : 'IP Address & ASN',
          val: `${di.ipAddress || (isAr ? 'غير متوفر' : 'N/A')} (${di.asn || (isAr ? 'غير محدد' : 'N/A')})`,
        },
        {
          label: isAr ? 'سجلات CNAME والتحويل' : 'CNAME Delegation',
          val: di.dnsRecords.cname && di.dnsRecords.cname.length > 0
            ? di.dnsRecords.cname.join(', ')
            : isAr ? 'لا توجد سجلات CNAME (نطاق رئيسي Apex)' : 'None (Apex Domain)',
        },
        {
          label: isAr ? 'سجلات تصريح الشهادات CAA' : 'CAA Certificate Authorization',
          val: di.dnsRecords.caa && di.dnsRecords.caa.length > 0
            ? di.dnsRecords.caa.join(', ')
            : isAr ? 'غير محددة في DNS' : 'None specified',
        },
        {
          label: isAr ? 'حالة مصادقة أمان DNSSEC' : 'DNSSEC Validation',
          val: di.dnsRecords.dnssecValidated === true
            ? isAr ? 'مفعّل ومطابق تشفيرياً' : 'Validated Cryptographically'
            : isAr ? 'غير مفعّل / غير موقّع' : 'Unsigned / Not Validated',
        },
      ];

      ctx.save();
      ctx.font = `500 13px ${this.fontSans}`;
      let totalDnsLines = 0;
      const renderedDnsItems: { lines: string[] }[] = [];
      for (const it of dnsItems) {
        const fullTxt = `${it.label}: ${it.val}`;
        const lines = wrapTextLines(ctx, fullTxt, textW);
        renderedDnsItems.push({ lines });
        totalDnsLines += lines.length;
      }
      ctx.restore();

      const box2H = 46 + totalDnsLines * 20 + 12;
      if (this.ensureSpace(box2H + 14)) {
        const curY = this.y;
        ctx.save();
        ctx.fillStyle = '#FFFFFF';
        ctx.strokeStyle = '#E2E8F0';
        ctx.lineWidth = 1.3;
        ctx.fillRect(MARGIN_X, curY, cardW, box2H);
        ctx.strokeRect(MARGIN_X, curY, cardW, box2H);

        ctx.fillStyle = '#059669';
        ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, box2H);

        ctx.textBaseline = 'top';
        ctx.direction = isAr ? 'rtl' : 'ltr';
        ctx.textAlign = isAr ? 'right' : 'left';
        const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

        ctx.fillStyle = '#0F172A';
        ctx.font = `800 15px ${this.fontSans}`;
        ctx.fillText(
          isAr ? 'استخبارات النطاق وسجلات نظام أسماء النطاقات (DNS Resolution & Architecture)' : 'Domain Intelligence & DNS Records',
          textStartX,
          curY + 12
        );

        ctx.fillStyle = '#F1F5F9';
        ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

        let textY = curY + 44;
        ctx.font = `500 13px ${this.fontSans}`;
        ctx.fillStyle = '#334155';
        for (const it of renderedDnsItems) {
          for (const ln of it.lines) {
            ctx.fillText(ln, textStartX, textY);
            textY += 20;
          }
        }
        ctx.restore();
        this.y = curY + box2H + 14;
        this.markPageHasContent();
      }
    }

    // --- Box 3: SSL/TLS Certificate Telemetry ---
    if (report.tlsIntel) {
      const t = report.tlsIntel;
      const tlsItems: { label: string; val: string }[] = [
        {
          label: isAr ? 'حالة التشفير والاعتماد' : 'HTTPS & CA Trust',
          val: isAr
            ? `HTTPS: ${t.httpsAvailable ? 'متاح' : 'غير متوفر'} · الشهادة: ${t.authorized ? 'موثوقة رسمياً' : 'غير موثوقة'}`
            : `HTTPS: ${t.httpsAvailable ? 'Available' : 'Unavailable'} · Trust: ${t.authorized ? 'Trusted CA' : 'Untrusted'}`,
        },
        {
          label: isAr ? 'البروتوكول والتشفير' : 'Protocol & Cipher',
          val: t.protocol || (isAr ? 'غير محدد' : 'Unknown'),
        },
        {
          label: isAr ? 'الجهة المُصدِرة للشهادة' : 'Certificate Issuer',
          val: t.issuer || (isAr ? 'غير متوفر' : 'Unknown'),
        },
        {
          label: isAr ? 'صلاحية الشهادة وتاريخ الانتهاء' : 'Certificate Validity & Expiry',
          val: t.validTo ? t.validTo.slice(0, 10) : (isAr ? 'غير متوفر' : 'Unknown'),
        },
      ];
      if (t.sharedWildcardSanNote) {
        tlsItems.push({
          label: isAr ? 'نطاقات SAN البديلة / Wildcard' : 'SAN / Wildcard Scope',
          val: t.sharedWildcardSanNote,
        });
      }

      ctx.save();
      ctx.font = `500 13px ${this.fontSans}`;
      let totalTlsLines = 0;
      const renderedTlsItems: { lines: string[] }[] = [];
      for (const it of tlsItems) {
        const fullTxt = `${it.label}: ${it.val}`;
        const lines = wrapTextLines(ctx, fullTxt, textW);
        renderedTlsItems.push({ lines });
        totalTlsLines += lines.length;
      }
      ctx.restore();

      const box3H = 46 + totalTlsLines * 20 + 12;
      if (this.ensureSpace(box3H + 14)) {
        const curY = this.y;
        ctx.save();
        ctx.fillStyle = '#FFFFFF';
        ctx.strokeStyle = '#E2E8F0';
        ctx.lineWidth = 1.3;
        ctx.fillRect(MARGIN_X, curY, cardW, box3H);
        ctx.strokeRect(MARGIN_X, curY, cardW, box3H);

        ctx.fillStyle = t.authorized && t.httpsAvailable ? '#16A34A' : '#DC2626';
        ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, box3H);

        ctx.textBaseline = 'top';
        ctx.direction = isAr ? 'rtl' : 'ltr';
        ctx.textAlign = isAr ? 'right' : 'left';
        const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

        ctx.fillStyle = '#0F172A';
        ctx.font = `800 15px ${this.fontSans}`;
        ctx.fillText(
          isAr ? 'شهادة التشفير الرقمي وبروتوكول النقل الآمن (SSL/TLS Cryptographic Telemetry)' : 'SSL/TLS Certificate & Transport Security',
          textStartX,
          curY + 12
        );

        ctx.fillStyle = '#F1F5F9';
        ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

        let textY = curY + 44;
        ctx.font = `500 13px ${this.fontSans}`;
        ctx.fillStyle = '#334155';
        for (const it of renderedTlsItems) {
          for (const ln of it.lines) {
            ctx.fillText(ln, textStartX, textY);
            textY += 20;
          }
        }
        ctx.restore();
        this.y = curY + box3H + 16;
        this.markPageHasContent();
      }
    }

    return true;
  }

  /**
   * Section 9: Multi-Page Discovery framed card (Page 6)
   */
  public drawPageDiscoverySection(): boolean {
    const isAr = this.isRtl;
    const lang = this.lang;
    const ctx = this.ctx;
    const pd = this.report.pageDiscovery;

    if (
      !this.drawSectionTitle(
        isAr
          ? '٩. استكشاف وفحص الصفحات الداخلية للموقع'
          : '9. Multi-Page Website Discovery & Inspection'
      )
    ) {
      return false;
    }

    const cardW = CONTENT_WIDTH;
    const paddingX = 20;
    const textW = cardW - paddingX * 2 - 10;

    const pages = pd?.pages || [];
    const items = pages.slice(0, 6).map((pg) => ({
      url: pg.url,
      role: pg.pageType,
      reason: pg.reason[lang],
    }));

    ctx.save();
    ctx.font = `500 13px ${this.fontSans}`;
    let totalLines = 0;
    const renderedItems: { lines: string[] }[] = [];
    if (items.length > 0) {
      for (const it of items) {
        const text = `[${it.role}] ${it.url} — ${it.reason}`;
        const lines = wrapTextLines(ctx, text, textW);
        renderedItems.push({ lines });
        totalLines += lines.length;
      }
    } else {
      const noneText = isAr
        ? 'فحص أحادي للصفحة الرئيسية — لم يتم رصد صفحات استدعاء داخلية إضافية'
        : 'Single-page inspection — no secondary internal pages discovered';
      const lines = wrapTextLines(ctx, noneText, textW);
      renderedItems.push({ lines });
      totalLines += lines.length;
    }
    ctx.restore();

    const boxH = 46 + totalLines * 20 + 12;
    if (!this.ensureSpace(boxH + 14)) return false;

    const curY = this.y;
    ctx.save();
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E2E8F0';
    ctx.lineWidth = 1.3;
    ctx.fillRect(MARGIN_X, curY, cardW, boxH);
    ctx.strokeRect(MARGIN_X, curY, cardW, boxH);

    ctx.fillStyle = '#0284C7';
    ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, boxH);

    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';
    const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

    ctx.fillStyle = '#0F172A';
    ctx.font = `800 15px ${this.fontSans}`;
    ctx.fillText(
      isAr
        ? `الصفحات المكتشفة بالهيكل الداخلي للموقع (${pages.length} صفحة)`
        : `Discovered Internal Pages (${pages.length} Pages)`,
      textStartX,
      curY + 12
    );

    ctx.fillStyle = '#F1F5F9';
    ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

    let textY = curY + 44;
    ctx.font = `500 13px ${this.fontSans}`;
    ctx.fillStyle = '#334155';
    for (const it of renderedItems) {
      for (const ln of it.lines) {
        ctx.fillText(ln, textStartX, textY);
        textY += 20;
      }
    }
    ctx.restore();
    this.y = curY + boxH + 14;
    this.markPageHasContent();
    return true;
  }

  /**
   * Section 10: External Threat Intelligence Feeds framed card (Page 6)
   */
  public drawThreatProvidersSection(): boolean {
    const isAr = this.isRtl;
    const lang = this.lang;
    const ctx = this.ctx;
    const providers = this.report.threatProviders || [];

    if (
      !this.drawSectionTitle(
        isAr ? '١٠. مزودو استخبارات التهديدات الخارجية' : '10. External Threat Intelligence Feeds'
      )
    ) {
      return false;
    }

    const cardW = CONTENT_WIDTH;
    const paddingX = 20;
    const textW = cardW - paddingX * 2 - 10;

    ctx.save();
    ctx.font = `500 13px ${this.fontSans}`;
    let totalLines = 0;
    const renderedItems: string[][] = [];
    for (const p of providers) {
      const summary = isAr
        ? `${p.providerName} [${tOperationalState(p.operationalState, lang)} · ${p.status}] (النطاق: ${p.matchScope || 'عام'}): ${p.verdictDetail.ar}`
        : `${p.providerName} [${tOperationalState(p.operationalState, lang)} · ${p.status}] (Scope: ${p.matchScope || 'general'}): ${p.verdictDetail.en}`;
      const lines = wrapTextLines(ctx, summary, textW);
      renderedItems.push(lines);
      totalLines += lines.length;
    }
    ctx.restore();

    const boxH = 46 + totalLines * 20 + 12;
    if (!this.ensureSpace(boxH + 14)) return false;

    const curY = this.y;
    ctx.save();
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E2E8F0';
    ctx.lineWidth = 1.3;
    ctx.fillRect(MARGIN_X, curY, cardW, boxH);
    ctx.strokeRect(MARGIN_X, curY, cardW, boxH);

    ctx.fillStyle = '#374151';
    ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, boxH);

    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';
    const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

    ctx.fillStyle = '#0F172A';
    ctx.font = `800 15px ${this.fontSans}`;
    ctx.fillText(
      isAr ? 'قواعد بيانات السمعة وتحليل التهديدات العالمية المتزامنة' : 'Synchronized Global Threat & Reputation Feeds',
      textStartX,
      curY + 12
    );

    ctx.fillStyle = '#F1F5F9';
    ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

    let textY = curY + 44;
    ctx.font = `500 13px ${this.fontSans}`;
    ctx.fillStyle = '#334155';
    for (const lines of renderedItems) {
      for (const ln of lines) {
        ctx.fillText(ln, textStartX, textY);
        textY += 20;
      }
    }
    ctx.restore();
    this.y = curY + boxH + 14;
    this.markPageHasContent();
    return true;
  }

  /**
   * Discovered Files & Download Verification Card (Page 6)
   * With 1-click live scan link to the platform and external threat intelligence references.
   */
  public drawFilesAndDownloadsCard(): boolean {
    const isAr = this.isRtl;
    const ctx = this.ctx;
    const report = this.report;
    const fa = report.fileAnalysis;

    const cardW = CONTENT_WIDTH;
    const paddingX = 20;
    const textW = cardW - paddingX * 2 - 12;

    const platformOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://scanlinksm.app';
    const targetUrl = report.finalDestinationUrl || report.submittedUrl;
    const directScanUrl = `${platformOrigin}/?url=${encodeURIComponent(targetUrl)}`;

    const linesToDraw: { label: string; lines: string[]; isWarning?: boolean }[] = [];

    // 1. Direct file payload info if present
    if (fa?.directFile) {
      const df = fa.directFile;
      const sizeKb = ((df.sizeBytes ?? 0) / 1024).toFixed(1);
      const isWarn = df.riskFlag === 'high' || df.riskFlag === 'critical' || df.riskFlag === 'medium';
      const sigLabel = df.detectedSignature || 'N/A';
      const riskLabel = df.riskFlag.toUpperCase();
      const catLabel = tFileDownloadCategory(df.downloadCategory, this.lang);
      linesToDraw.push({
        label: isAr ? 'الملف المحمّل المفحوص' : 'Analyzed Payload File',
        lines: [
          isAr
            ? `اسم الملف: ${df.filename} · التصنيف: ${catLabel} · الحجم: ${sizeKb} KB · البصمة السحرية: ${sigLabel}`
            : `File: ${df.filename} · Category: ${catLabel} · Size: ${sizeKb} KB · Magic Signature: ${sigLabel}`,
          `SHA-256: ${df.sha256 || '—'}`,
          isAr
            ? `التصنيف الأمني: ${riskLabel} (${isWarn ? 'تحذير: صيغة قابلة لتنفيذ أوامر أو تحميل مضلل' : 'تحميل طبيعي سليم تم التحقق من توقيعه'})`
            : `Classification: ${riskLabel} (${isWarn ? 'Warning: Hazardous executable or deceptive download' : 'Verified normal download with matching signature'})`,
        ],
        isWarning: isWarn,
      });
    } else if (fa?.discoveredDownloads && fa.discoveredDownloads.length > 0) {
      const dList = fa.discoveredDownloads.slice(0, 5).map(
        (d) => `${d.filename} (${d.extension}) [${tFileDownloadCategory(d.downloadCategory, this.lang)}] -> ${d.url}`
      );
      linesToDraw.push({
        label: isAr
          ? `روابط التنزيل المكتشفة في كود الصفحة (${fa.discoveredDownloads.length} ملف)`
          : `Discovered Download Resource Links (${fa.discoveredDownloads.length} Files)`,
        lines: dList,
      });
    } else {
      linesToDraw.push({
        label: isAr ? 'حالة فحص وتدقيق الملفات' : 'File & Payload Inspection Status',
        lines: [
          isAr
            ? 'سليم — لم يتم رصد ملفات تنفيذية مشبوهة أو حمولات برمجية خبيثة تنزل تلقائياً في الصفحة المفحوصة.'
            : 'Clean — No suspicious executable payloads or automatic download hazards detected in inspected DOM.',
        ],
      });
    }

    // 2. Direct Platform Scan URL with interactive explanation
    linesToDraw.push({
      label: isAr
        ? 'رابط الفحص الفوري المباشر عبر منصة Scan Link SM'
        : 'Scan Link SM Live Platform Verification Link',
      lines: [
        directScanUrl,
        isAr
          ? 'ملاحظة تشغيلية: عند فتح هذا الرابط، يبدأ محرك المنصة فحصاً حياً فورياً للنطاق والملف مباشرة أمامك لاكتشاف وتفنيد أي مخاطر.'
          : 'Notice: Opening this URL automatically triggers an instant live scan of the target domain and payload live in front of the analyst.',
      ],
    });

    // 3. Multi-Engine Threat Intelligence Lookup & Sandbox References
    const vtRef = fa?.directFile?.sha256
      ? `https://www.virustotal.com/gui/file/${fa.directFile.sha256}`
      : `https://www.virustotal.com/gui/domain/${encodeURIComponent(report.domainIntel?.registrableDomain || targetUrl)}`;
    const haRef = 'https://www.hybrid-analysis.com/';
    const mdRef = 'https://metadefender.opswat.com/';

    linesToDraw.push({
      label: isAr
        ? 'مراجع فحص نوع الملف وقواعد التهديدات الدولية (Multi-Engine Feeds)'
        : 'Multi-Engine Threat Intelligence References & Automated Sandboxes',
      lines: [
        `VirusTotal: ${vtRef}`,
        `Hybrid Analysis Malware Sandbox: ${haRef}`,
        `OPSWAT MetaDefender Multi-Scanner: ${mdRef}`,
      ],
    });

    // Calculate height
    ctx.save();
    ctx.font = `500 13px ${this.fontSans}`;
    let totalLinesCount = 0;
    const computedBlocks: { label: string; wrappedLines: string[]; isWarning?: boolean }[] = [];
    for (const block of linesToDraw) {
      const wrapped: string[] = [];
      for (const raw of block.lines) {
        wrapped.push(...wrapTextLines(ctx, raw, textW));
      }
      computedBlocks.push({ label: block.label, wrappedLines: wrapped, isWarning: block.isWarning });
      totalLinesCount += wrapped.length + 1;
    }
    ctx.restore();

    const cardH = 50 + totalLinesCount * 21 + 16;
    if (!this.ensureSpace(cardH + 16)) return false;

    const curY = this.y;
    ctx.save();
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E2E8F0';
    ctx.lineWidth = 1.3;
    ctx.fillRect(MARGIN_X, curY, cardW, cardH);
    ctx.strokeRect(MARGIN_X, curY, cardW, cardH);

    const hasWarning = computedBlocks.some((b) => b.isWarning);
    ctx.fillStyle = hasWarning ? '#DC2626' : '#16A34A';
    ctx.fillRect(isAr ? MARGIN_X + cardW - 5 : MARGIN_X, curY, 5, cardH);

    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';
    const textStartX = isAr ? MARGIN_X + cardW - paddingX - 6 : MARGIN_X + paddingX + 6;

    ctx.fillStyle = '#0F172A';
    ctx.font = `800 15px ${this.fontSans}`;
    ctx.fillText(
      isAr
        ? 'فحص وتدقيق الملفات المحملة والمكتشفة وروابط التحقق المباشر'
        : 'Payload & Download Verification & Direct Live Scan Access',
      textStartX,
      curY + 12
    );

    ctx.fillStyle = '#F1F5F9';
    ctx.fillRect(MARGIN_X + 10, curY + 36, cardW - 20, 1);

    let blockY = curY + 44;
    for (const b of computedBlocks) {
      ctx.font = `700 13px ${this.fontSans}`;
      ctx.fillStyle = b.isWarning ? '#B91C1C' : '#0F172A';
      ctx.fillText(b.label, textStartX, blockY);
      blockY += 20;

      ctx.font = `500 12.5px ${this.fontMono}`;
      ctx.fillStyle = '#334155';
      for (const ln of b.wrappedLines) {
        ctx.fillText(ln, textStartX, blockY);
        blockY += 19;
      }
      blockY += 6;
    }

    ctx.restore();
    this.y = curY + cardH + 16;
    this.markPageHasContent();
    return true;
  }

  /**
   * Dedicated Final Page: Platform Rights, Ownership & Security Attestation
   */
  public drawPlatformRightsPage(): void {
    const ctx = this.ctx;
    const isAr = this.isRtl;

    const top = HEADER_SAFE_Y;
    this.y = top;

    // Center Logo
    if (this.logoImg && this.logoImg.naturalWidth > 0) {
      const targetH = 80;
      const aspect = this.logoImg.naturalWidth / Math.max(1, this.logoImg.naturalHeight);
      const targetW = Math.min(320, targetH * aspect);
      const logoX = MARGIN_X + Math.round((CONTENT_WIDTH - targetW) / 2);
      ctx.drawImage(this.logoImg, logoX, this.y, targetW, targetH);
      this.y += targetH + 18;
    } else {
      ctx.save();
      ctx.textBaseline = 'top';
      ctx.font = `800 32px ${this.fontSans}`;
      ctx.fillStyle = '#111827';
      ctx.textAlign = 'center';
      ctx.fillText('Scan Link SM', A4_WIDTH_PX / 2, this.y);
      ctx.restore();
      this.y += 48;
    }

    // Main Title
    ctx.save();
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = 'center';
    ctx.fillStyle = '#111827';
    ctx.font = `800 24px ${this.fontSans}`;
    const mainTitle = isAr
      ? 'حقوق المنصة والملكية الفكرية والاعتماد الأمني'
      : 'Platform Rights, Intellectual Property & Engine Attestation';
    ctx.fillText(mainTitle, A4_WIDTH_PX / 2, this.y);
    this.y += 32;

    ctx.font = `600 15px ${this.fontSans}`;
    ctx.fillStyle = '#FF263F';
    const subTitle = isAr
      ? 'وثيقة الاعتماد الأمني الرسمية الصادرة عن منصة Scan Link SM'
      : 'Official Security Intelligence Attestation Issued by Scan Link SM';
    ctx.fillText(subTitle, A4_WIDTH_PX / 2, this.y);
    this.y += 28;

    // Accent line
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X + 100, this.y, CONTENT_WIDTH - 200, 1.5);
    this.y += 28;
    ctx.restore();

    const tX = isAr ? A4_WIDTH_PX - MARGIN_X - 24 : MARGIN_X + 24;

    // Box 1: Platform Ownership & Developer Info
    const box1H = 170;
    ctx.save();
    ctx.fillStyle = '#FAFAFA';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.4;
    ctx.fillRect(MARGIN_X, this.y, CONTENT_WIDTH, box1H);
    ctx.strokeRect(MARGIN_X, this.y, CONTENT_WIDTH, box1H);

    ctx.fillStyle = '#FF263F';
    ctx.fillRect(isAr ? MARGIN_X + CONTENT_WIDTH - 6 : MARGIN_X, this.y, 6, box1H);

    let b1Y = this.y + 20;
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';

    ctx.font = `800 18px ${this.fontSans}`;
    ctx.fillStyle = '#111827';
    ctx.fillText(isAr ? '١. بيانات المالك والمطور والملكية الفكرية' : '1. Official Ownership & Intellectual Property', tX, b1Y);
    b1Y += 32;

    ctx.font = `600 15.5px ${this.fontSans}`;
    ctx.fillStyle = '#374151';
    ctx.fillText(isAr ? 'المالك والمؤسس والمطور:' : 'Owner, Founder & Developer:', tX, b1Y);
    ctx.fillStyle = '#111827';
    ctx.font = `800 16px ${this.fontSans}`;
    const ownerNameOffset = isAr ? -190 : 220;
    ctx.fillText('Mohamed Abu AlSaud SM', tX + ownerNameOffset, b1Y);
    b1Y += 28;

    ctx.font = `600 15.5px ${this.fontSans}`;
    ctx.fillStyle = '#374151';
    ctx.fillText(isAr ? 'الحساب الرسمي المعتمد:' : 'Official Registered Handle:', tX, b1Y);
    ctx.fillStyle = '#FF263F';
    ctx.font = `800 15.5px ${this.fontMono}`;
    const handleOffset = isAr ? -190 : 220;
    ctx.fillText('@A_Y_TR', tX + handleOffset, b1Y);
    b1Y += 28;

    ctx.font = `600 15px ${this.fontSans}`;
    ctx.fillStyle = '#4B5563';
    ctx.fillText(
      isAr
        ? 'المنصة: Scan Link SM — نظام استخباراتي أمني مستقل لتحليل وفحص سلامة الروابط والمواقع.'
        : 'Platform: Scan Link SM — Autonomous Website & URL Threat Intelligence Engine.',
      tX,
      b1Y
    );
    ctx.restore();
    this.y += box1H + 22;

    // Box 2: Zero AI & Deterministic Architecture Guarantee
    const box2H = 150;
    ctx.save();
    ctx.fillStyle = '#FFFFFF';
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.4;
    ctx.fillRect(MARGIN_X, this.y, CONTENT_WIDTH, box2H);
    ctx.strokeRect(MARGIN_X, this.y, CONTENT_WIDTH, box2H);

    ctx.fillStyle = '#0284C7';
    ctx.fillRect(isAr ? MARGIN_X + CONTENT_WIDTH - 6 : MARGIN_X, this.y, 6, box2H);

    let b2Y = this.y + 20;
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';

    ctx.font = `800 18px ${this.fontSans}`;
    ctx.fillStyle = '#111827';
    ctx.fillText(isAr ? '٢. اعتماد المحرك الحتمي (Zero AI / Deterministic Engine)' : '2. Deterministic Engine & Zero-AI Attestation', tX, b2Y);
    b2Y += 32;

    ctx.font = `500 15px ${this.fontSans}`;
    ctx.fillStyle = '#374151';
    const zeroAiDesc = isAr
      ? 'نظام Scan Link SM يعمل بالكامل كبرمجية حتمية (Deterministic) قائمة على فحص وتحليل حقيقي للبنية والمحتوى والشيفرة المصدرية وسجلات DNS وشهادات التشفير، بدون أي استدعاءات لنماذج ذكاء اصطناعي أو LLM، مما يمنع الهلوسات البرمجية ويضمن نتائج تدقيق قطعية موثوقة.'
      : 'Scan Link SM operates exclusively on a 100% deterministic, rule-based security architecture with live DOM parsing, static code analysis, and verified threat feeds. Zero LLMs or AI inference models are used, guaranteeing reproducible forensic results without generative hallucinations.';
    const zLines = wrapTextLines(ctx, zeroAiDesc, CONTENT_WIDTH - 48);
    for (const ln of zLines) {
      ctx.fillText(ln, tX, b2Y);
      b2Y += 24;
    }
    ctx.restore();
    this.y += box2H + 22;

    // Box 3: Verification Stamp & Scan Telemetry
    const box3H = 160;
    ctx.save();
    ctx.fillStyle = '#FFF5F6';
    ctx.strokeStyle = '#FECDD3';
    ctx.lineWidth = 1.4;
    ctx.fillRect(MARGIN_X, this.y, CONTENT_WIDTH, box3H);
    ctx.strokeRect(MARGIN_X, this.y, CONTENT_WIDTH, box3H);

    ctx.fillStyle = '#DC2626';
    ctx.fillRect(isAr ? MARGIN_X + CONTENT_WIDTH - 6 : MARGIN_X, this.y, 6, box3H);

    let b3Y = this.y + 20;
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';

    ctx.font = `800 18px ${this.fontSans}`;
    ctx.fillStyle = '#991B1B';
    ctx.fillText(isAr ? '٣. البصمة الرقمية وبيانات توثيق التقرير' : '3. Digital Fingerprint & Audit Telemetry', tX, b3Y);
    b3Y += 30;

    ctx.font = `600 14px ${this.fontMono}`;
    ctx.fillStyle = '#111827';
    ctx.fillText(`Scan ID: ${this.report.scanId}`, tX, b3Y);
    b3Y += 24;

    const formattedDate = new Date(this.report.completedAt).toISOString().replace('T', ' ').slice(0, 19);
    ctx.fillText(`Completed: ${formattedDate} UTC  |  Duration: ${(this.report.durationMs / 1000).toFixed(2)}s`, tX, b3Y);
    b3Y += 24;

    ctx.fillText(`Risk Score: ${this.report.riskScore}/100  |  Classification: ${this.report.classification}  |  Verdict: ${this.report.verdict}`, tX, b3Y);
    b3Y += 24;

    ctx.font = `500 13px ${this.fontSans}`;
    ctx.fillStyle = '#6B7280';
    ctx.fillText(
      isAr
        ? 'المعايير المعتمدة: RFC 5280 X.509 · Public Suffix List (PSL) · DNSSEC · abuse.ch Feeds · OWASP Security Standards'
        : 'Standards: RFC 5280 X.509 · Public Suffix List · DNSSEC · abuse.ch Feeds · OWASP Security Standards',
      tX,
      b3Y
    );
    ctx.restore();
    this.y += box3H + 24;

    // Bottom Prominent Red Verification Seal
    const sealW = 420;
    const sealH = 100;
    const sealX = MARGIN_X + Math.round((CONTENT_WIDTH - sealW) / 2);
    const sealY = this.y + 10;

    ctx.save();
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(sealX, sealY, sealW, sealH);
    ctx.strokeStyle = '#FF263F';
    ctx.lineWidth = 2.5;
    ctx.strokeRect(sealX, sealY, sealW, sealH);

    ctx.strokeStyle = '#FF263F';
    ctx.lineWidth = 1;
    ctx.strokeRect(sealX + 5, sealY + 5, sealW - 10, sealH - 10);

    ctx.textBaseline = 'alphabetic';
    ctx.direction = 'ltr';
    ctx.textAlign = 'center';

    ctx.fillStyle = '#FF263F';
    ctx.font = `800 16px ${this.fontSans}`;
    ctx.fillText('SCAN LINK SM · OFFICIAL ATTESTATION SEAL', sealX + sealW / 2, sealY + 36);

    ctx.fillStyle = '#111827';
    ctx.font = `700 13px ${this.fontMono}`;
    ctx.fillText('MOHAMED ABU ALSAUD SM · @A_Y_TR', sealX + sealW / 2, sealY + 62);

    ctx.fillStyle = '#52525B';
    ctx.font = `600 11.5px ${this.fontSans}`;
    ctx.fillText(
      isAr ? 'تقرير موثق ومحمى بحقوق الملكية الفكرية' : 'CRYPTOGRAPHICALLY VERIFIED & REGISTERED',
      sealX + sealW / 2,
      sealY + 84
    );
    ctx.restore();

    this.y = sealY + sealH + 30;
    this.markPageHasContent();
  }

  /**
   * Draws a standalone framed card with left/right colored accent stripe for Level B PDF pages.
   * Ensures exact bounds fit inside the dedicated A4 page without spilling to a 4th page.
   */
  private drawLevelBCard(
    title: string,
    accentColor: string,
    lines: { text: string; mono?: boolean; color?: string }[],
    bgColor = '#FFFFFF'
  ): void {
    const ctx = this.ctx;
    const isAr = this.isRtl;
    const padX = 22;
    const textW = CONTENT_WIDTH - padX * 2 - 12;

    const wrapped: { text: string; mono?: boolean; color?: string }[] = [];
    ctx.save();
    for (const item of lines) {
      ctx.font = item.mono ? `500 13px ${this.fontMono}` : `500 14.5px ${this.fontSans}`;
      const parts = wrapTextLines(ctx, item.text, textW);
      for (const p of parts) {
        wrapped.push({ text: p, mono: item.mono, color: item.color });
      }
    }
    ctx.restore();

    const maxLines = Math.max(1, Math.floor((MAX_BODY_Y - this.y - 72) / 21));
    const displayLines = wrapped.slice(0, maxLines);
    const boxH = 52 + displayLines.length * 21 + 14;
    if (this.y + boxH > MAX_BODY_Y) return;

    const top = this.y;
    ctx.save();
    ctx.fillStyle = bgColor;
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.4;
    ctx.fillRect(MARGIN_X, top, CONTENT_WIDTH, boxH);
    ctx.strokeRect(MARGIN_X, top, CONTENT_WIDTH, boxH);

    ctx.fillStyle = accentColor;
    ctx.fillRect(isAr ? MARGIN_X + CONTENT_WIDTH - 6 : MARGIN_X, top, 6, boxH);

    let cy = top + 14;
    ctx.textBaseline = 'top';
    ctx.direction = isAr ? 'rtl' : 'ltr';
    ctx.textAlign = isAr ? 'right' : 'left';
    const xText = isAr ? MARGIN_X + CONTENT_WIDTH - padX - 8 : MARGIN_X + padX + 8;

    ctx.fillStyle = '#111827';
    ctx.font = `800 16.5px ${this.fontSans}`;
    ctx.fillText(title, xText, cy);
    cy += 30;

    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X + 12, cy - 6, CONTENT_WIDTH - 24, 1);

    for (const ln of displayLines) {
      ctx.direction = ln.mono ? 'ltr' : isAr ? 'rtl' : 'ltr';
      ctx.textAlign = isAr ? 'right' : 'left';
      ctx.font = ln.mono ? `500 13px ${this.fontMono}` : `500 14.5px ${this.fontSans}`;
      ctx.fillStyle = ln.color || '#374151';
      ctx.fillText(ln.text, xText, cy);
      cy += 21;
    }

    ctx.restore();
    this.y = top + boxH + 16;
    this.markPageHasContent();
  }

  /**
   * Renders 3 consecutive, standalone A4 pages dedicated exclusively to Level B (Scan B):
   * - Level B Page 1: LevelBScanBox Summary, Metadata, 3-Axis Impact & Runtime Screenshot
   * - Level B Page 2: Rendered DOM, Runtime Redirects, Permission Events & Outbound Network Requests
   * - Level B Page 3: Cross-Layer Analytical Correlation, Scoring Contribution & Recommendations
   */
  public drawLevelBThreePages(levelBImg: HTMLImageElement | null): void {
    const isAr = this.isRtl;
    const lang = this.lang;
    const lb = this.report.levelB;
    const lbStatus =
      lb?.status ?? (this.report.analysisLevels?.levelBIsolatedBrowser.performed ? 'executed' : 'unavailable');
    const isExecuted = lbStatus === 'executed';
    const statusColor =
      lbStatus === 'executed'
        ? '#16A34A'
        : lbStatus === 'blocked_by_ssrf'
          ? '#DC2626'
          : '#D97706';

    const statusText =
      lbStatus === 'executed'
        ? isAr
          ? 'تم التنفيذ بنجاح (Executed)'
          : 'Executed Successfully'
        : lbStatus === 'blocked_by_ssrf'
          ? isAr
            ? 'محظور عبر حارس SSRF'
            : 'Blocked by SSRF Guard'
          : lbStatus === 'failed'
            ? isAr
              ? 'فشل التنفيذ الخارجي (Failed)'
              : 'Failed (Remote Execution Error)'
            : lbStatus === 'disabled'
              ? isAr
                ? 'معطّل من الجلسة (Disabled)'
                : 'Disabled in Session'
              : isAr
                ? 'غير منفّذ / غير متاح (Not Executed / Unavailable)'
                : 'Not Executed / Unavailable';

    // =========================================================
    // LEVEL B — PAGE 1 OF 3: Main Scan B Box & Runtime Screenshot
    // =========================================================
    if (!this.newPage()) return;
    this.drawSectionTitle(
      isAr
        ? 'القسم B (١ / ٣): صندوق Scan B — الملخص التنفيذي ولقطة الشاشة'
        : 'Level B Section (1 / 3): LevelBScanBox Summary & Runtime Screenshot'
    );

    const providerText =
      lb?.providerLabel?.[lang] ||
      (isAr ? 'خدمة متصفح خارجي سحابي (.env)' : 'External Cloud Browser Service (.env)');
    const durationText = lb?.durationMs !== undefined ? `${lb.durationMs} ms` : '—';
    const finalUrlText = lb?.finalUrl || this.report.finalDestinationUrl || '—';
    const impactText = isExecuted
      ? isAr
        ? `تغطية +${Math.abs(lb?.coverageImpact ?? 0)}% · أثر درجة المخاطر: 0 (تحليل حقيقي)`
        : `Coverage +${Math.abs(lb?.coverageImpact ?? 0)}% · Risk Penalty: 0 (Live telemetry)`
      : isAr
        ? `خصم الثقة ${lb?.confidenceImpact ?? -12}% · خصم التغطية ${lb?.coverageImpact ?? -15}% · أثر المخاطر: 0 (لا افتراض بدون رصد)`
        : `Confidence ${lb?.confidenceImpact ?? -12}% · Coverage ${lb?.coverageImpact ?? -15}% · Risk Penalty: 0 (No fabricated penalty)`;

    const page1Lines: { text: string; mono?: boolean; color?: string }[] = [
      {
        text: `${isAr ? 'الحالة التشغيلية:' : 'Operational Status:'} ${statusText}`,
        color: statusColor,
      },
      {
        text: `${isAr ? 'المزود ووضع التشغيل:' : 'Provider & Mode:'} ${providerText} (${lb?.executionMode || 'unavailable'})`,
      },
      {
        text: `${isAr ? 'زمن التنفيذ:' : 'Execution Duration:'} ${durationText}   |   ${isAr ? 'التوقيت:' : 'Executed At:'} ${lb?.executedAt || this.report.completedAt}`,
        mono: true,
      },
      {
        text: `${isAr ? 'الرابط النهائي وقت التشغيل:' : 'Runtime Final URL:'} ${finalUrlText}`,
        mono: true,
      },
      {
        text: `${isAr ? 'التأثير على المحاور الثلاثة:' : '3-Axis Impact:'} ${impactText}`,
      },
      {
        text: `${isAr ? 'الملخص التنفيذي:' : 'Executive Summary:'} ${
          lb?.executiveSummary?.[lang] ||
          this.report.analysisLevels?.levelBIsolatedBrowser.reason?.[lang] ||
          statusText
        }`,
      },
    ];
    if (!isExecuted && lb?.errorReason?.[lang]) {
      page1Lines.push({
        text: `${isAr ? 'سبب عدم التنفيذ:' : 'Non-Execution Reason:'} ${lb.errorReason[lang]}`,
        color: '#B45309',
      });
    }

    this.drawLevelBCard(
      isAr ? 'بطاقة الحالة والهوية التشغيلية — Scan B' : 'Scan B Operational Header & Telemetry Card',
      statusColor,
      page1Lines,
      '#F9FAFB'
    );

    const remainingH = MAX_BODY_Y - this.y - 24;
    if (levelBImg && levelBImg.naturalWidth > 0 && remainingH > 220) {
      const ctx = this.ctx;
      const boxTop = this.y;
      const frameH = Math.min(540, remainingH);
      const innerPad = 18;
      const availW = CONTENT_WIDTH - innerPad * 2;
      const availH = frameH - 72;
      const aspect = levelBImg.naturalWidth / Math.max(1, levelBImg.naturalHeight);
      let drawW = availW;
      let drawH = drawW / aspect;
      if (drawH > availH) {
        drawH = availH;
        drawW = drawH * aspect;
      }

      ctx.save();
      ctx.fillStyle = '#FFFFFF';
      ctx.strokeStyle = '#E5E7EB';
      ctx.lineWidth = 1.4;
      ctx.fillRect(MARGIN_X, boxTop, CONTENT_WIDTH, frameH);
      ctx.strokeRect(MARGIN_X, boxTop, CONTENT_WIDTH, frameH);

      ctx.textBaseline = 'top';
      ctx.direction = isAr ? 'rtl' : 'ltr';
      ctx.textAlign = isAr ? 'right' : 'left';
      ctx.fillStyle = '#111827';
      ctx.font = `800 16px ${this.fontSans}`;
      ctx.fillText(
        isAr ? 'لقطة الشاشة الملتقطة في Level B' : 'Level B Runtime Captured Screenshot',
        isAr ? MARGIN_X + CONTENT_WIDTH - innerPad : MARGIN_X + innerPad,
        boxTop + 14
      );

      ctx.direction = 'ltr';
      ctx.textAlign = isAr ? 'left' : 'right';
      ctx.fillStyle = '#6B7280';
      ctx.font = `600 12.5px ${this.fontMono}`;
      const dimLabel = `${lb?.screenshot?.viewport || 'desktop'}${
        lb?.screenshot?.width && lb?.screenshot?.height
          ? ` · ${lb.screenshot.width}x${lb.screenshot.height}`
          : ''
      }`;
      ctx.fillText(dimLabel, isAr ? MARGIN_X + innerPad : MARGIN_X + CONTENT_WIDTH - innerPad, boxTop + 16);

      const imgX = MARGIN_X + Math.round((CONTENT_WIDTH - drawW) / 2);
      const imgY = boxTop + 48;
      ctx.drawImage(levelBImg, imgX, imgY, drawW, drawH);
      ctx.strokeStyle = '#D1D5DB';
      ctx.strokeRect(imgX, imgY, drawW, drawH);
      ctx.restore();
      this.y = boxTop + frameH + 14;
      this.markPageHasContent();
    } else {
      const missingText =
        lb?.screenshot?.missingReason?.[lang] ||
        (isAr
          ? 'لم تُلتقط لقطة شاشة في Level B لأن الجلسة السحابية الخارجية غير متاحة أو لم ترجع إطاراً بصرياً.'
          : 'No Level B runtime screenshot was captured because external cloud browser execution was unavailable or returned no visual frame.');
      this.drawLevelBCard(
        isAr ? 'لقطة الشاشة الملتقطة في Level B (غير متوفرة)' : 'Level B Runtime Screenshot (Not Captured)',
        '#D97706',
        [
          { text: missingText, color: '#374151' },
          {
            text: isAr
              ? `إعداد العرض المطلوب: ${lb?.screenshot?.viewport || 'desktop'} · الحالة: Not Executed / Unavailable`
              : `Requested Viewport: ${lb?.screenshot?.viewport || 'desktop'} · Status: Not Executed / Unavailable`,
            mono: true,
          },
        ],
        '#FFFBEB'
      );
    }

    // =========================================================
    // LEVEL B — PAGE 2 OF 3: Dynamic Behavior, Permissions & Network Requests
    // =========================================================
    if (!this.newPage()) return;
    this.drawSectionTitle(
      isAr
        ? 'القسم B (٢ / ٣): السلوك الديناميكي، الصلاحيات، والطلبات الشبكية الصادرة'
        : 'Level B Section (2 / 3): Dynamic Behavior, Permissions & Outbound Network Requests'
    );

    const redirects = lb?.redirects ?? [];
    const dom = lb?.domSummary;
    const domAndRedirectLines: { text: string; mono?: boolean; color?: string }[] = [];
    if (dom) {
      domAndRedirectLines.push({
        text: isAr
          ? `العنوان النهائي: ${dom.title || '—'} · نماذج DOM: ${dom.dynamicFormCount} · حقول حساسة: ${dom.sensitiveInputCount} · Iframes: ${dom.dynamicIframeCount} · سكربتات: ${dom.dynamicScriptCount} · الكلمات: ${dom.wordCount}`
          : `Title: ${dom.title || '—'} · Forms: ${dom.dynamicFormCount} · Sensitive Inputs: ${dom.sensitiveInputCount} · Iframes: ${dom.dynamicIframeCount} · Scripts: ${dom.dynamicScriptCount} · Words: ${dom.wordCount}`,
      });
      if (dom.notableElements.length > 0) {
        domAndRedirectLines.push({
          text: `${isAr ? 'عناصر ديناميكية بارزة:' : 'Notable DOM Elements:'} ${dom.notableElements.slice(0, 6).join(' · ')}`,
          mono: true,
        });
      }
    } else {
      domAndRedirectLines.push({
        text: isAr
          ? 'لم تُلتقط بنية DOM نهائية لأن Level B لم يُنفّذ (لا توجد بيانات ملفّقة).'
          : 'No rendered DOM telemetry recorded because Level B did not execute (zero fabricated data).',
      });
    }
    if (redirects.length > 0) {
      for (const hop of redirects.slice(0, 4)) {
        domAndRedirectLines.push({
          text: `Redirect #${hop.step}${hop.statusCode ? ` [${hop.statusCode}]` : ''}: ${hop.url}${hop.note ? ` (${hop.note})` : ''}`,
          mono: true,
        });
      }
    } else {
      domAndRedirectLines.push({
        text: isAr
          ? 'التحويلات المرصودة وقت التشغيل: 0 قفزات إضافية.'
          : 'Observed runtime redirects: 0 additional hops.',
      });
    }

    this.drawLevelBCard(
      isAr ? '١. حالة DOM النهائي وسلسلة التحويلات وقت التشغيل' : '1. Rendered DOM State & Runtime Redirects',
      '#0284C7',
      domAndRedirectLines
    );

    const permEvents = lb?.permissionEvents ?? [];
    const permLines: { text: string; mono?: boolean; color?: string }[] =
      permEvents.length > 0
        ? permEvents.slice(0, 6).map((ev) => ({
            text: `[${ev.kind.toUpperCase()} · ${ev.trigger} -> ${ev.outcome}] ${ev.api} — ${ev.detail[lang]}`,
            color:
              ev.kind === 'camera' || ev.kind === 'microphone' || ev.kind === 'clipboard' || ev.trigger === 'on_load'
                ? '#DC2626'
                : '#374151',
          }))
        : [
            {
              text: isExecuted
                ? isAr
                  ? 'لم تُرصد محاولات طلب الكاميرا أو الميكروفون أو الموقع أو الحافظة أو الإشعارات أثناء الجلسة.'
                  : 'No runtime camera, microphone, geolocation, clipboard, or notification permission prompts observed.'
                : isAr
                  ? 'غير منفّذ: لم يتم رصد أحداث صلاحيات وقت التشغيل (راجع تدقيق الصلاحيات الساكن من Level A).'
                  : 'Not Executed: No runtime permission events observed (refer to Level A static permission audit).',
            },
          ];

    this.drawLevelBCard(
      isAr ? `٢. سجل محاولات الصلاحيات والأحداث (${permEvents.length})` : `2. Runtime Permission Attempts & Behavioral Events (${permEvents.length})`,
      permEvents.length > 0 ? '#DC2626' : '#16A34A',
      permLines
    );

    const netReqs = lb?.networkRequests ?? [];
    const netLines: { text: string; mono?: boolean; color?: string }[] =
      netReqs.length > 0
        ? netReqs.slice(0, 9).map((req) => ({
            text: `[${req.method}] ${req.domain}${req.path || '/'} (${req.resourceType || 'fetch'}) -> ${req.channelCategory}`,
            mono: true,
            color:
              req.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
              req.channelCategory === 'WEBHOOK_OR_BOT_SINK'
                ? '#DC2626'
                : req.channelCategory === 'IP_AND_DEVICE_PROFILING'
                  ? '#D97706'
                  : req.channelCategory === 'UNVERIFIED_EXTERNAL'
                    ? '#0284C7'
                    : '#374151',
          }))
        : [
            {
              text: isExecuted
                ? isAr
                  ? 'لم تُرصد طلبات شبكية صادرة إلى وجهات خارجية أثناء جلسة التشغيل.'
                  : 'No outbound third-party network requests recorded during runtime execution.'
                : isAr
                  ? 'غير منفّذ: لم يتم تسجيل طلبات شبكية صادرة لأن خدمة المتصفح السحابي لم تُنفّذ.'
                  : 'Not Executed: No outbound runtime network requests recorded because Level B was unavailable.',
            },
          ];
    if (netReqs.length > 9) {
      netLines.push({
        text: isAr
          ? `... و${netReqs.length - 9} طلبات إضافية مسجلة في واجهة التقرير.`
          : `... and ${netReqs.length - 9} additional requests recorded in the report UI.`,
      });
    }

    this.drawLevelBCard(
      isAr ? `٣. الطلبات الشبكية الصادرة وتصنيف قنواتها (${netReqs.length})` : `3. Outbound Network Requests & Channel Classification (${netReqs.length})`,
      netReqs.some(
        (r) =>
          r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
          r.channelCategory === 'WEBHOOK_OR_BOT_SINK'
      )
        ? '#DC2626'
        : '#0284C7',
      netLines
    );

    // =========================================================
    // LEVEL B — PAGE 3 OF 3: Analytical Correlation & Recommendations
    // =========================================================
    if (!this.newPage()) return;
    this.drawSectionTitle(
      isAr
        ? 'القسم B (٣ / ٣): الربط التحليلي مع الطبقات الأخرى والتوصيات العملية'
        : 'Level B Section (3 / 3): Cross-Layer Analytical Correlation & Recommendations'
    );

    const taints = this.report.sourceIntel?.dataFlowTaints ?? [];
    const backdoors = this.report.sourceIntel?.plantedBackdoors ?? [];
    const decodedSecrets = this.report.urlEncryptionIntel?.decodedSecretsDetected ?? [];
    const xssStatus = this.report.xssAssessment?.status ?? 'safe';
    const flaggedFeeds = this.report.threatProviders.filter((p) => p.status === 'flagged');
    const unverifiedTx = (this.report.sourceIntel?.externalDataTransmissions ?? []).filter(
      (t) => t.harmClassification === 'unverified_external'
    );
    const maliciousTx = (this.report.sourceIntel?.externalDataTransmissions ?? []).filter((t) => t.isHarmful);

    const correlationLines: { text: string; mono?: boolean; color?: string }[] = [
      {
        text: isAr
          ? `• التحليل الثابت (AST Data-Flow): تم رصد ${taints.length} مسار تدفق/تسريب (${taints.slice(0, 2).map((t) => `${t.source}->${t.sink}`).join(', ') || 'لا يوجد'}) و ${maliciousTx.length} إرسال خبيث مؤكد و ${unverifiedTx.length} إرسال خارجي غير موثوق.`
          : `• Static AST Data-Flow: ${taints.length} taint flow(s) (${taints.slice(0, 2).map((t) => `${t.source}->${t.sink}`).join(', ') || 'none'}), ${maliciousTx.length} confirmed malicious outbound hook(s), ${unverifiedTx.length} unverified external destination(s).`,
        color: taints.length > 0 || maliciousTx.length > 0 ? '#DC2626' : '#374151',
      },
      {
        text: isAr
          ? `• فك تشفير الروابط والبيانات المخفية: ${decodedSecrets.length} مفتاح/توكن مفكوك من معاملات الرابط (${decodedSecrets.map((s) => `${s.param}:${s.kind}`).join(', ') || 'سليم — لا توجد مفاتيح مسربة'}).`
          : `• URL De-obfuscation & Payload Inspection: ${decodedSecrets.length} decoded credential/bot secret(s) (${decodedSecrets.map((s) => `${s.param}:${s.kind}`).join(', ') || 'none detected'}).`,
        color: decodedSecrets.length > 0 ? '#DC2626' : '#374151',
      },
      {
        text: isAr
          ? `• فحص ثغرات XSS والـ Backdoors المزروعة: حالة XSS هي (${xssStatus}) · مؤشرات الأبواب الخلفية المزروعة: ${backdoors.length}.`
          : `• Passive XSS & Planted Backdoors: XSS status is (${xssStatus}) · Planted backdoor/control hooks: ${backdoors.length}.`,
        color: xssStatus === 'high_risk' || backdoors.length > 0 ? '#DC2626' : '#374151',
      },
      {
        text: isAr
          ? `• مصادر التهديد الخارجية وتكامل Level B: ${flaggedFeeds.length} مصدر تهديد بلّغ عن الرابط · حالة Level B: ${statusText}.`
          : `• External Threat Intelligence & Level B Synergy: ${flaggedFeeds.length} flagged feed(s) · Level B state: ${statusText}.`,
      },
    ];

    this.drawLevelBCard(
      isAr ? '١. الربط التحليلي المتكامل (Level B + Level A + AST + XSS + Threat Intel)' : '1. Cross-Layer Forensic Correlation Matrix',
      '#111827',
      correlationLines
    );

    const covPct =
      this.report.inspectionCoveragePercent ??
      Math.round(
        (this.report.summaryStats.availableProviders /
          Math.max(1, this.report.summaryStats.totalProviders)) *
          100
      );
    const verdictImpactLines: { text: string; mono?: boolean; color?: string }[] = [
      {
        text: isAr
          ? `• الحكم النهائي: ${tClassification(this.report.classification, lang)} (${this.report.riskScore}/100) · الثقة: ${this.report.confidenceScore}% · تغطية الفحص: ${covPct}%`
          : `• Final Classification: ${tClassification(this.report.classification, lang)} (${this.report.riskScore}/100) · Confidence: ${this.report.confidenceScore}% · Coverage: ${covPct}%`,
        color: classificationColor(this.report.classification),
      },
      ...(this.report.scoreBreakdown || []).slice(0, 5).map((b) => ({
        text: `  [${b.delta >= 0 ? `+${b.delta}` : b.delta}] ${b.label[lang]}`,
      })),
    ];

    this.drawLevelBCard(
      isAr ? '٢. تأثير نتائج الفحص على التصنيف النهائي ومحاور التقييم الثلاثة' : '2. Impact on Final Risk Classification & 3-Axis Scoring',
      classificationColor(this.report.classification),
      verdictImpactLines,
      '#F9FAFB'
    );

    const recs: { text: string; color?: string }[] = [];
    if (this.report.riskScore >= 68 || taints.length > 0 || decodedSecrets.length > 0 || backdoors.length > 0) {
      recs.push({
        text: isAr
          ? '• تجنّب فتح الرابط أو منح صلاحيات الكاميرا أو الميكروفون أو الموقع الجغرافي أو الحافظة، ولا تُدخل أي بيانات شخصية أو كلمات مرور.'
          : '• Do not open this target or grant Camera, Microphone, Geolocation, or Clipboard permissions; never submit credentials or tokens.',
        color: '#DC2626',
      });
      recs.push({
        text: isAr
          ? '• قم بإلغاء وتدوير أي مفاتيح أو Bot Tokens مفكوكة من الرابط أو الشيفرة فوراً وحظر الوجهات المستلمة على جدار الحماية.'
          : '• Immediately revoke/rotate any exposed bot tokens or embedded credentials and block identified exfiltration endpoints.',
      });
    } else if (unverifiedTx.length > 0) {
      recs.push({
        text: isAr
          ? '• راجع نقاط الإرسال الخارجية غير الموثوقة (Unverified External) وتحقق من ملكيتها وملاءمتها لغرض الموقع قبل الاعتماد الإنتاجي.'
          : '• Review flagged unverified external outbound endpoints to confirm ownership and necessity prior to production trust.',
      });
    } else {
      recs.push({
        text: isAr
          ? '• لم تُرصد قنوات تسريب خطرة أو تفاعلات تجسس نشطة؛ حافظ على مراقبة سياسة أمان المحتوى (CSP) وتقييد الصلاحيات.'
          : '• No active surveillance exfiltration channels detected; continue enforcing strict Content-Security-Policy and Permissions-Policy headers.',
        color: '#16A34A',
      });
    }

    if (!isExecuted) {
      recs.push({
        text: isAr
          ? '• لتشغيل المراقبة الديناميكية الكاملة داخل Level B (لقطة الشاشة + طلبات الشبكة الحية + الصلاحيات)، اضبط متغيرات الخدمة السحابية الخارجية في ملف .env بالخادم دون تثبيت متصفح محلي.'
          : '• To enable full Level B live runtime inspection (screenshot, outbound network hooks, permission prompts), configure the External Cloud Browser credentials in server .env without local browser binaries.',
      });
    }
    recs.push({
      text: isAr
        ? '• اعتمد على تقارير الربط الموحّدة بين التحليل الساكن (Level A) والتنفيذ المعزول (Level B) مع التحقق من الصلاحيات قبل أي تفاعل.'
        : '• Correlate static AST findings (Level A) with isolated runtime telemetry (Level B) and verify permissions before user interaction.',
    });

    this.drawLevelBCard(
      isAr ? '٣. التوصيات الأمنية والعملية القابلة للتنفيذ' : '3. Practical Security & Operational Recommendations',
      '#0284C7',
      recs
    );
  }

  public finalizeToPdf(): void {
    // Filter out any unused or blank page ("وصفح مش مستخدمه احذفها")
    const validPages = this.pages.filter((p) => p.hasContent);
    const pagesToExport = validPages.length > 0 ? validPages.map((p) => p.canvas) : [this.pages[0].canvas];
    const totalPages = pagesToExport.length;

    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
      compress: true,
    });

    pagesToExport.forEach((canvas, idx) => {
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.save();
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#E5E7EB';
        ctx.fillRect(MARGIN_X, FOOTER_Y - 14, CONTENT_WIDTH, 1.5);

        ctx.fillStyle = '#4B5563';
        ctx.font = `600 15px ${this.fontSans}`;
        if (this.isRtl) {
          ctx.direction = 'rtl';
          ctx.textAlign = 'right';
          ctx.fillText(
            'Scan Link SM · المالك والمطور: Mohamed Abu AlSaud SM · @A_Y_TR',
            A4_WIDTH_PX - MARGIN_X,
            FOOTER_Y + 14
          );
          ctx.textAlign = 'left';
          ctx.fillText(
            `صفحة ${idx + 1} من ${totalPages}`,
            MARGIN_X,
            FOOTER_Y + 14
          );
        } else {
          ctx.direction = 'ltr';
          ctx.textAlign = 'left';
          ctx.fillText(
            'Scan Link SM · Owned & Developed by Mohamed Abu AlSaud SM · @A_Y_TR',
            MARGIN_X,
            FOOTER_Y + 14
          );
          ctx.textAlign = 'right';
          ctx.font = `600 15px ${this.fontMono}`;
          ctx.fillText(
            `Page ${idx + 1} / ${totalPages}`,
            A4_WIDTH_PX - MARGIN_X,
            FOOTER_Y + 14
          );
        }
        ctx.restore();
      }

      if (idx > 0) pdf.addPage();
      const imgData = canvas.toDataURL('image/png', 0.96);
      pdf.addImage(imgData, 'PNG', 0, 0, 210, 297, undefined, 'FAST');
    });

    pdf.save(`scan-link-sm-report-${this.report.scanId.slice(0, 8)}.pdf`);
  }
}

export async function downloadScanReportPdf(report: ScanReport, lang: Language): Promise<void> {
  if (typeof document !== 'undefined' && 'fonts' in document) {
    try {
      await document.fonts.ready;
    } catch {
      // ignore font loading timeout
    }
  }

  const safeCoverSrc = safeImageDataUrl(report.screenshot?.imageDataUrl);
  const safeLevelBSrc = safeImageDataUrl(report.levelB?.screenshot?.dataUrl);

  const [logoImg, screenshotImg, faviconImg, levelBImg] = await Promise.all([
    loadImageElement(OFFICIAL_BRAND_ASSETS.lightLogo),
    safeCoverSrc ? loadImageElement(safeCoverSrc) : Promise.resolve(null),
    report.siteFaviconDataUrl ? loadImageElement(report.siteFaviconDataUrl) : Promise.resolve(null),
    safeLevelBSrc ? loadImageElement(safeLevelBSrc) : Promise.resolve(null),
  ]);

  const doc = new WhitePageComposer(report, lang, logoImg, faviconImg);
  const isAr = lang === 'ar';

  // ==========================================
  // PAGE 1: Cover Header & Title + Executive Summary + Website Screenshot
  // ==========================================
  doc.drawCoverHeader();
  doc.drawExecutiveSummary();
  if (screenshotImg) {
    doc.drawScreenshotBlock(screenshotImg);
  }

  // ==========================================
  // PAGE 2: Risk Classification Level Diagram & Analytics Charts & 5 Pillars
  // ==========================================
  doc.newPage();
  doc.drawClassificationLevelDiagram();
  doc.drawAnalyticsCharts();

  if (report.separatedAssessments) {
    if (
      doc.drawSectionTitle(
        isAr ? '١. التقييمات الخمسة المفصولة مستقلاً' : '1. Five Separated Security Pillars'
      )
    ) {
      const pillars = [
        report.separatedAssessments.domainAuthenticity,
        report.separatedAssessments.threatIntelligence,
        report.separatedAssessments.websiteSecurity,
        report.separatedAssessments.sslTlsStatus,
        report.separatedAssessments.redirectAnalysis,
      ];
      doc.drawKeyValueBlock(
        pillars.map((p) => ({
          label: `${p.title[lang]} [${tStatus(p.status, lang)}]`,
          value: `${p.verdict[lang]} — ${p.detail[lang]}`,
          accent: p.status === 'failed' ? '#DC2626' : p.status === 'warning' ? '#D97706' : '#0284C7',
        }))
      );
    }
  }

  // ==========================================
  // DEDICATED LEVEL B SECTION: 3 Consecutive Standalone Pages (1/3, 2/3, 3/3)
  // ==========================================
  doc.drawLevelBThreePages(levelBImg);

  // ==========================================
  // PAGE 3+: Sections 2, 3, 4 (First of the 2 pages for sections 2..6)
  // ==========================================
  doc.newPage();
  if (report.domainAuthenticity) {
    const auth = report.domainAuthenticity;
    if (
      doc.drawSectionTitle(
        isAr ? '٢. التحقق الرسمي من النطاق وتدقيق النطاقات الفرعية' : '2. Official Domain Verification & Subdomain Audit'
      )
    ) {
      const rows: { label: string; value: string; accent?: string }[] = [
        {
          label: isAr ? 'حالة التحقق الرسمي للنطاق' : 'Official Registry Status',
          value: `${auth.label[lang]} — ${isAr ? 'النطاق المسجّل' : 'Registrable Domain'}: ${auth.registrableDomain} (${isAr ? 'الفرعي' : 'Subdomain'}: ${auth.subdomain || (isAr ? 'رئيسي' : 'apex')})`,
          accent:
            auth.status === 'official_verified' || auth.status === 'official_subdomain'
              ? '#0284C7'
              : auth.status === 'brand_lookalike'
                ? '#D97706'
                : '#111827',
        },
        {
          label: isAr ? 'مصادر التحقق والملكية' : 'Verification & Ownership Sources',
          value: `${auth.corroborationSources.filter((c) => c.verified).map((c) => c.source).join(', ') || (isAr ? 'تحليل البنية فقط' : 'Structural Registry Only')} · ${auth.disclaimer[lang]}`,
        },
      ];
      if (auth.hostingMetadata?.isSharedPaas) {
        rows.push({
          label: isAr ? 'بيئة الاستضافة المشتركة (Shared PaaS)' : 'Shared PaaS Hosting Context',
          value: isAr
            ? `المزود: ${auth.hostingMetadata.hostingProvider || 'Shared PaaS'} · ملكية النطاق المخصص: ${auth.hostingMetadata.customDomainOwnership === 'verified' ? 'موثقة' : 'غير موثقة (معلوماتي)'} · الهوية: ${auth.hostingMetadata.websiteIdentity.ar}`
            : `Provider: ${auth.hostingMetadata.hostingProvider || 'Shared PaaS'} · Custom Domain Ownership: ${auth.hostingMetadata.customDomainOwnership} · Identity: ${auth.hostingMetadata.websiteIdentity.en}`,
          accent: '#0284C7',
        });
      }
      if (report.domainIntel?.subdomainAnalysis) {
        const sa = report.domainIntel.subdomainAnalysis;
        rows.push({
          label: isAr ? 'تدقيق النطاقات الفرعية وتفويض CNAME' : 'Subdomain Hierarchy & CNAME Delegation',
          value: `${sa.assessment[lang]}${sa.cnameTargets.length > 0 ? ` · CNAME: ${sa.cnameTargets.join(', ')}` : ''}`,
        });
      }
      doc.drawKeyValueBlock(rows);
    }
  }

  if (report.topReasons && report.topReasons.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr ? '٣. أبرز الأسباب المؤثرة في التقييم' : '3. Key Factors Driving This Verdict'
      )
    ) {
      doc.drawBulletList(report.topReasons.map((r) => r[lang]));
    }
  }

  if (report.scoreBreakdown && report.scoreBreakdown.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr ? '٤. تفصيل احتساب درجة المخاطر' : '4. Deterministic Score Breakdown'
      )
    ) {
      doc.drawBulletList(
        report.scoreBreakdown.map(
          (b) => `${b.label[lang]} (${b.delta >= 0 ? `+${b.delta}` : b.delta})`
        ),
        '#111827'
      );
    }
  }

  // ==========================================
  // PAGE 4: Sections 5, 6 (Second of the 2 pages for sections 2..6)
  // ==========================================
  doc.newPage();
  if (report.evidenceBuckets) {
    const eb = report.evidenceBuckets;
    if (
      doc.drawSectionTitle(
        isAr ? '٥. مصفوفة تصنيف الأدلة والتعارض' : '5. Categorized Evidence & Conflict Matrix'
      )
    ) {
      const bucketRows: { label: string; value: string; accent?: string }[] = [];
      if (eb.confirmed.length > 0) {
        bucketRows.push({
          label: isAr ? 'أدلة مؤكدة' : 'Confirmed Evidence',
          value: eb.confirmed.map((x) => x[lang]).join(' · '),
          accent: '#111827',
        });
      }
      if (eb.suspicious.length > 0) {
        bucketRows.push({
          label: isAr ? 'مؤشرات مشبوهة' : 'Suspicious Signals',
          value: eb.suspicious.map((x) => x[lang]).join(' · '),
          accent: '#D97706',
        });
      }
      if (eb.inconclusive.length > 0) {
        bucketRows.push({
          label: isAr ? 'غير مكتمل أو غير حاسم' : 'Inconclusive / Unavailable',
          value: eb.inconclusive.map((x) => x[lang]).join(' · '),
          accent: '#52525B',
        });
      }
      if (eb.conflicting.length > 0) {
        bucketRows.push({
          label: isAr ? 'أدلة متعارضة' : 'Conflicting Evidence',
          value: eb.conflicting.map((x) => x[lang]).join(' · '),
          accent: '#DC2626',
        });
      }
      if (bucketRows.length > 0) doc.drawKeyValueBlock(bucketRows);
    }
  }

  if (report.sourceIntel) {
    const si = report.sourceIntel;
    if (
      doc.drawSectionTitle(
        isAr
          ? '٦. تحليل سورس HTML وسلوك JavaScript والنطاقات الفرعية المكتشفة'
          : '6. HTML Source, JS Behavioral Forensics & Discovered Subdomains'
      )
    ) {
      const srcRows: { label: string; value: string; accent?: string }[] = [];
      if (si.jsBehaviorSummary) {
        const jb = si.jsBehaviorSummary;
        const yes = isAr ? 'مرصود' : 'Detected';
        const no = isAr ? 'سليم' : 'Clean';
        srcRows.push({
          label: isAr ? 'ملخص التحليل السلوكي لـ JavaScript بالذاكرة' : 'Static JS Behavioral Summary',
          value: isAr
            ? `تغيير وجهة النموذج ديناميكياً: ${jb.dynamicFormActionRewrite ? yes : no} · التقاط حقول كلمات المرور: ${jb.passwordFieldDomHooks ? yes : no} · سحب المحافظ/الحافظة: ${jb.walletDrainerPattern ? yes : no} · إطارات مخفية: ${jb.hiddenOverlayIframes} · مصائد منع الفحص: ${jb.antiDebugTraps ? yes : no}`
            : `Form Action Hijack: ${jb.dynamicFormActionRewrite ? yes : no} · Password DOM Hooks: ${jb.passwordFieldDomHooks ? yes : no} · Crypto/Clipboard Drainer: ${jb.walletDrainerPattern ? yes : no} · Hidden Overlay Iframes: ${jb.hiddenOverlayIframes} · Anti-Debug Traps: ${jb.antiDebugTraps ? yes : no}`,
          accent:
            jb.dynamicFormActionRewrite || jb.passwordFieldDomHooks || jb.walletDrainerPattern
              ? '#DC2626'
              : '#16A34A',
        });
      }
      if (si.obfuscationVsMinifiedNote) {
        srcRows.push({
          label: isAr ? 'تصنيف الشفرة المضغوطة مقابل التعتيم' : 'Minified vs Obfuscated JS Classification',
          value: si.obfuscationVsMinifiedNote[lang],
        });
      }
      if (si.suspiciousCodeSignals.length > 0) {
        srcRows.push({
          label: isAr ? 'إشارات الشيفرة المرصودة في السورس' : 'Observed Source Code Signals',
          value: si.suspiciousCodeSignals
            .slice(0, 6)
            .map((s) => `${s.indicator} (${s.contextAssessment[lang]})`)
            .join(' · '),
          accent: '#D97706',
        });
      }
      if (si.cookieAudit) {
        const ca = si.cookieAudit;
        const catSummary = ca.cookiesDetected
          .slice(0, 6)
          .map((c) => `${c.name} [${tCookieCategory(c.category, lang)}]`)
          .join(', ');
        srcRows.push({
          label: isAr ? 'تدقيق ملفات تعريف الارتباط والموافقة (Cookie Intelligence)' : 'Cookie Classification & Consent Intelligence',
          value: `${ca.summary[lang]}${catSummary ? ` · Cookies: ${catSummary}` : ''}`,
          accent: ca.hasMaliciousCookieBehavior
            ? '#DC2626'
            : ca.consentVerification?.privacyViolationDetected || ca.setsAdvertisingCookies
              ? '#D97706'
              : '#16A34A',
        });
      }
      if (si.advertisingIntel) {
        const ad = si.advertisingIntel;
        srcRows.push({
          label: isAr ? 'استخبارات الإعلانات والتتبع (Advertising Intelligence)' : 'Advertising & Tracking Intelligence',
          value: `${tAdIntelState(ad.status, lang)} — ${ad.summary[lang]}`,
          accent:
            ad.status === 'malicious_advertising'
              ? '#DC2626'
              : ad.status === 'suspicious_advertising' || ad.status === 'undeclared_tracking'
                ? '#D97706'
                : '#16A34A',
        });
      }
      if (si.workersDetected && (si.workersDetected.hasServiceWorker || si.workersDetected.hasWebWorker)) {
        srcRows.push({
          label: isAr ? 'فحص Service / Web Workers بالخلفية' : 'Background Service & Web Workers',
          value: si.workersDetected.summary[lang],
          accent: si.workersDetected.isMaliciousOrSuspicious ? '#DC2626' : '#16A34A',
        });
      }
      if (si.externalDataTransmissions && si.externalDataTransmissions.length > 0) {
        srcRows.push({
          label: isAr
            ? `نقاط الإرسال الخارجية المرصودة (${si.externalDataTransmissions.length})`
            : `Outbound JS Data Transmissions (${si.externalDataTransmissions.length})`,
          value: si.externalDataTransmissions
            .slice(0, 6)
            .map(
              (tx) =>
                `${tx.destinationHost} (${tx.method}${tx.sourceScript ? ` @ ${tx.sourceScript}` : ''}) -> ${tx.harmClassification}`
            )
            .join(' · '),
          accent: si.externalDataTransmissions.some((t) => t.isHarmful) ? '#DC2626' : '#0284C7',
        });
      }
      if (si.discoveredSubdomains && si.discoveredSubdomains.length > 0) {
        srcRows.push({
          label: isAr
            ? `النطاقات الفرعية المكتشفة بالموقع (${si.discoveredSubdomains.length})`
            : `Discovered Site Subdomains (${si.discoveredSubdomains.length})`,
          value: si.discoveredSubdomains
            .slice(0, 10)
            .map(
              (sub) =>
                `${sub.host} [${sub.role}]${sub.resolvedIps?.length ? ` -> ${sub.resolvedIps[0]}` : ''}${sub.cnameChain?.length ? ` (CNAME: ${sub.cnameChain[0]})` : ''}`
            )
            .join(' · '),
        });
      }
      if (srcRows.length > 0) doc.drawKeyValueBlock(srcRows);
    }
  }

  if (report.xssAssessment) {
    const xa = report.xssAssessment;
    const xssTitle = isAr
      ? 'فحص ثغرات XSS وحقن DOM في الموقع المستهدف (Passive XSS Audit)'
      : 'Target Passive XSS & DOM Sink Security Assessment';
    if (doc.drawSectionTitle(xssTitle)) {
      const xssAccent =
        xa.status === 'high_risk'
          ? '#DC2626'
          : xa.status === 'potential_weakness'
            ? '#D97706'
            : xa.status === 'safe'
              ? '#16A34A'
              : '#6B7280';
      const xssRows: { label: string; value: string; accent?: string }[] = [
        {
          label: isAr ? 'حالة فحص XSS' : 'XSS Audit Status',
          value: `${xa.label[lang]} — ${xa.summary[lang]}`,
          accent: xssAccent,
        },
        {
          label: isAr ? 'مؤشرات الفحص' : 'Telemetry Counts',
          value: isAr
            ? `انعكاس معاملات غير معقّمة: ${xa.reflectedParamsCount} · منافذ DOM الخطرة: ${xa.domSinkCount} · سياسة CSP: ${xa.cspStatus} · نقص HttpOnly بالجلسة: ${xa.httpOnlySessionCookiesMissing ? 'نعم' : 'لا'}`
            : `Reflected Params: ${xa.reflectedParamsCount} · DOM XSS Sinks: ${xa.domSinkCount} · CSP Policy: ${xa.cspStatus} · Session Cookie Missing HttpOnly: ${xa.httpOnlySessionCookiesMissing ? 'Yes' : 'No'}`,
        },
      ];
      if (xa.remediationGuidance.length > 0) {
        xssRows.push({
          label: isAr ? 'إرشادات الحماية والتصحيح' : 'XSS Remediation Guidance',
          value: xa.remediationGuidance.map((g) => g[lang]).join(' · '),
        });
      }
      doc.drawKeyValueBlock(xssRows);
    }
  }

  // ==========================================
  // PAGE 5: Section 7 (Structured Boxes & Frames) & Section 8 (12 Core Dimensions)
  // ==========================================
  doc.newPage();
  doc.drawNetworkAndTlsSection();

  if (report.websiteIntelligenceReport && report.websiteIntelligenceReport.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr
          ? '٨. تقرير SM للاستخبارات المعمقة للموقع (١٢ محوراً)'
          : '8. SM Website Intelligence Report (12 Core Dimensions)'
      )
    ) {
      const pdfRows = report.websiteIntelligenceReport.map((item) => {
        const stLabel =
          item.status === 'inspected'
            ? isAr
              ? 'تم الفحص'
              : 'Inspected'
            : item.status === 'not_present'
              ? isAr
                ? 'غير موجود'
                : 'Not Present'
              : isAr
                ? 'تعذر الفحص'
                : 'Unavailable';
        return {
          label: `${item.title[lang]} [${stLabel}]`,
          value: item.summary[lang],
        };
      });
      if (report.analysisLevels) {
        pdfRows.push({
          label: isAr ? 'المستوى A (التحليل الساكن)' : 'Level A (Static Analysis)',
          value: report.analysisLevels.levelAStatic.summary[lang],
        });
        pdfRows.push({
          label: isAr ? 'المستوى B (المتصفح المعزول)' : 'Level B (Isolated Browser)',
          value: report.analysisLevels.levelBIsolatedBrowser.reason[lang],
        });
      }
      doc.drawKeyValueBlock(pdfRows);
    }
  }

  // ==========================================
  // PAGE 6: Sections 9, 10 & Discovered Files / Download Verification Card
  // ==========================================
  doc.newPage();
  doc.drawPageDiscoverySection();
  doc.drawThreatProvidersSection();
  doc.drawFilesAndDownloadsCard();

  // ==========================================
  // SECTION 11: Detailed Findings (Boxes & Frames distributed over up to 4 pages)
  // ==========================================
  const orderedFindings = [
    ...report.findings.filter((f) => f.status === 'failed'),
    ...report.findings.filter((f) => f.status === 'warning'),
    ...report.findings.filter((f) => f.status === 'unknown'),
    ...report.findings.filter((f) => f.status === 'pass'),
  ];

  if (orderedFindings.length > 0) {
    const maxFindingsPages = 4;
    const findingsPerSheet = Math.max(1, Math.ceil(orderedFindings.length / maxFindingsPages));

    for (let fPage = 0; fPage < maxFindingsPages; fPage++) {
      const slice = orderedFindings.slice(fPage * findingsPerSheet, (fPage + 1) * findingsPerSheet);
      if (slice.length === 0) break;

      doc.newPage();
      const secTitle = fPage === 0
        ? (isAr ? '١١. السجل الكامل لنتائج الفحص والأدلة والتوصيات (١ من ٤)' : '11. Detailed Findings, Forensic Evidence & Guidance (1 / 4)')
        : (isAr ? `١١. السجل الكامل لنتائج الفحص والأدلة — تابع (${fPage + 1} من ٤)` : `11. Detailed Findings — Cont. (${fPage + 1} / 4)`);

      doc.drawSectionTitle(secTitle);
      for (const item of slice) {
        doc.drawFindingCard(item);
      }
    }
  }

  // ==========================================
  // FINAL PAGE: Dedicated Platform Rights Page (حقوق المنصة والملكية الفكرية)
  // ==========================================
  doc.newPage();
  doc.drawPlatformRightsPage();

  doc.finalizeToPdf();
}
