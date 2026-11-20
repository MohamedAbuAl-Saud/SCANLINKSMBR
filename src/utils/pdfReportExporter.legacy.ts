import { jsPDF } from 'jspdf';
import type { Language, RiskClassification, ScanReport } from '../types/scan';
import { OFFICIAL_BRAND_ASSETS } from '../components/BrandMark';
import { tClassification, tOperationalState, tSeverity, tStatus, tVerdict } from '../i18n/translations';

const A4_WIDTH_PX = 1240;
const A4_HEIGHT_PX = 1754;
const MARGIN_X = 72;
const CONTENT_WIDTH = A4_WIDTH_PX - MARGIN_X * 2;
const HEADER_SAFE_Y = 72;
const FOOTER_Y = A4_HEIGHT_PX - 70;
const MAX_BODY_Y = FOOTER_Y - 34;
const MAX_PDF_PAGES = 12;

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
  private pages: HTMLCanvasElement[] = [];
  private canvas!: HTMLCanvasElement;
  private ctx!: CanvasRenderingContext2D;
  private y = HEADER_SAFE_Y;
  private pageLimitReached = false;
  private readonly isRtl: boolean;
  private readonly lang: Language;
  private readonly report: ScanReport;
  private readonly logoImg: HTMLImageElement | null;
  private readonly fontSans: string;
  private readonly fontMono = '"JetBrains Mono", ui-monospace, SFMono-Regular, monospace';

  constructor(report: ScanReport, lang: Language, logoImg: HTMLImageElement | null) {
    this.report = report;
    this.lang = lang;
    this.isRtl = lang === 'ar';
    this.logoImg = logoImg;
    this.fontSans = this.isRtl
      ? '"IBM Plex Sans Arabic", "Plus Jakarta Sans", system-ui, sans-serif'
      : '"Plus Jakarta Sans", "Manrope", system-ui, sans-serif';
    this.newPage();
  }

  public isFull(): boolean {
    return this.pageLimitReached;
  }

  private newPage(): boolean {
    if (this.pages.length >= MAX_PDF_PAGES) {
      this.pageLimitReached = true;
      return false;
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
    this.pages.push(c);
    this.y = HEADER_SAFE_Y;
    return true;
  }

  private ensureSpace(neededHeight: number): boolean {
    if (this.pageLimitReached) return false;
    if (this.y + neededHeight > MAX_BODY_Y) {
      if (!this.newPage()) {
        return false;
      }
      this.drawContinuationHeader();
    }
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

    // 1. Top Header Band: Official Logo (clean, never colliding with stamp or title)
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

    // 3. Dedicated Separator Rule Below Header Band (guarantees zero overlap)
    const ruleY = headerTop + headerBandHeight + 18; // 186
    ctx.save();
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X, ruleY, CONTENT_WIDTH, 1.5);
    ctx.restore();

    // 4. Title & Scan Metadata safely below separator
    this.y = ruleY + 28; // 214

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
    ).slice(0, 4);

    ctx.font = `500 15px ${this.fontMono}`;
    const subPrefix = this.lang === 'ar' ? 'الرابط المُدخَل: ' : 'Submitted: ';
    const finPrefix = this.lang === 'ar' ? 'الوجهة النهائية: ' : 'Final URL: ';
    const subLines = wrapTextLines(ctx, `${subPrefix}${this.report.submittedUrl}`, CONTENT_WIDTH - 48).slice(0, 2);
    const finLines = wrapTextLines(ctx, `${finPrefix}${this.report.finalDestinationUrl}`, CONTENT_WIDTH - 48).slice(0, 2);
    ctx.restore();

    const boxH = 154 + (subLines.length + finLines.length) * 22 + recLines.length * 25 + 24;
    if (!this.ensureSpace(boxH + 22)) return;

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

    let cy = top + 24;
    ctx.fillStyle = verdictColor;
    ctx.font = `800 26px ${this.fontSans}`;
    ctx.fillText(tClassification(this.report.classification, this.lang), xPad, cy);
    cy += 36;

    ctx.fillStyle = '#111827';
    ctx.font = `700 20px ${this.fontSans}`;
    ctx.fillText(
      `${this.lang === 'ar' ? 'الحكم النهائي:' : 'Final Verdict:'} ${tVerdict(this.report.verdict, this.lang)}`,
      xPad,
      cy
    );
    cy += 32;

    ctx.fillStyle = '#374151';
    ctx.font = `600 17px ${this.fontSans}`;
    ctx.fillText(
      `${this.lang === 'ar' ? 'درجة المخاطر' : 'Risk Score'}: ${this.report.riskScore}/100   ·   ${this.lang === 'ar' ? 'الموثوقية' : 'Confidence'}: ${this.report.confidenceScore}% (${this.report.confidenceLabel})   ·   ${this.lang === 'ar' ? 'التغطية' : 'Coverage'}: ${cov}%`,
      xPad,
      cy
    );
    cy += 34;

    // URLs in crisp monospace
    ctx.fillStyle = '#4B5563';
    ctx.font = `500 15px ${this.fontMono}`;
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    for (const ln of subLines) {
      ctx.fillText(ln, xPad, cy);
      cy += 22;
    }
    for (const ln of finLines) {
      ctx.fillText(ln, xPad, cy);
      cy += 22;
    }
    cy += 10;

    // Recommendation
    ctx.fillStyle = '#111827';
    ctx.font = `500 17px ${this.fontSans}`;
    for (const ln of recLines) {
      ctx.fillText(ln, xPad, cy);
      cy += 25;
    }

    ctx.restore();
    this.y = top + boxH + 26;
  }

  /**
   * Visual Classification Level Diagram & Risk Gauge (0-100 + 6 classification levels + threshold scale)
   */
  public drawClassificationLevelDiagram(): void {
    const boxH = 300;
    if (!this.ensureSpace(boxH + 26)) return;

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
      top + 18
    );

    // Left / Right split: Circular Gauge + 6 Classification Tiers Ladder + Bottom Threshold Ruler
    const gaugeX = this.isRtl ? A4_WIDTH_PX - MARGIN_X - 145 : MARGIN_X + 145;
    const gaugeY = top + 140;
    const radius = 66;

    // Gauge track
    ctx.beginPath();
    ctx.arc(gaugeX, gaugeY, radius, 0, Math.PI * 2);
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 15;
    ctx.stroke();

    // Active risk arc
    const startAngle = -Math.PI / 2;
    const arcSweep = Math.max(0.06, (score / 100) * Math.PI * 2);
    ctx.beginPath();
    ctx.arc(gaugeX, gaugeY, radius, startAngle, startAngle + arcSweep);
    ctx.strokeStyle = accent;
    ctx.lineWidth = 15;
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
    ctx.fillText('/ 100', gaugeX, gaugeY + 20);

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

    const ladderStartX = this.isRtl ? MARGIN_X + 24 : MARGIN_X + 286;
    const ladderWidth = CONTENT_WIDTH - 310;
    const cols = 3;
    const cellW = (ladderWidth - 20) / cols;
    const cellH = 54;

    tiers.forEach((tier, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const cx = ladderStartX + col * (cellW + 10);
      const cy = top + 66 + row * (cellH + 10);
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

      // Accent color stripe (right side in RTL, left side in LTR)
      ctx.fillStyle = tier.color;
      ctx.fillRect(this.isRtl ? cx + cellW - 5 : cx, cy, 5, cellH);

      ctx.textBaseline = 'top';
      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const tx = this.isRtl ? cx + cellW - 14 : cx + 14;
      ctx.fillStyle = active ? tier.color : '#111827';
      ctx.font = `${active ? 800 : 700} 14px ${this.fontSans}`;
      ctx.fillText(tier.label, tx, cy + 9);

      ctx.direction = 'ltr';
      ctx.fillStyle = '#6B7280';
      ctx.font = `600 12px ${this.fontMono}`;
      ctx.fillText(tier.range, tx, cy + 31);
    });

    // Bottom Horizontal Risk Ruler (0 -> 50 -> 68 -> 82 -> 100)
    const barX = MARGIN_X + 28;
    const barY = top + 244;
    const barW = CONTENT_WIDTH - 56;
    const barH = 16;

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
    ctx.font = `600 12px ${this.fontMono}`;
    for (const mark of [0, 15, 50, 68, 82, 100]) {
      const mx = barX + (mark / 100) * barW;
      ctx.fillStyle = '#374151';
      ctx.fillRect(mx - 1, barY - 4, 2, barH + 8);
      ctx.fillText(`${mark}`, mx, barY + barH + 7);
    }

    // Score pointer triangle
    const ptrX = barX + (score / 100) * barW;
    ctx.fillStyle = '#111827';
    ctx.beginPath();
    ctx.moveTo(ptrX, barY - 2);
    ctx.lineTo(ptrX - 8, barY - 14);
    ctx.lineTo(ptrX + 8, barY - 14);
    ctx.closePath();
    ctx.fill();

    ctx.restore();
    this.y = top + boxH + 26;
  }

  /**
   * Visual Charts Block: (1) Findings Status Donut Chart & (2) Technical Sections Breakdown Bar Chart
   */
  public drawAnalyticsCharts(): void {
    const boxH = 388;
    if (!this.ensureSpace(boxH + 26)) return;

    const top = this.y;
    const ctx = this.ctx;
    const stats = this.report.summaryStats;
    const total = Math.max(1, stats.passedChecks + stats.warningChecks + stats.failedChecks + stats.incompleteChecks);

    const statusSlices = [
      {
        label: this.lang === 'ar' ? 'سليم' : 'Passed',
        value: stats.passedChecks,
        color: '#16A34A',
      },
      {
        label: this.lang === 'ar' ? 'تحذير' : 'Warning',
        value: stats.warningChecks,
        color: '#F59E0B',
      },
      {
        label: this.lang === 'ar' ? 'فشل' : 'Failed',
        value: stats.failedChecks,
        color: '#EF233C',
      },
      {
        label: this.lang === 'ar' ? 'غير مكتمل' : 'Unknown',
        value: stats.incompleteChecks,
        color: '#71717A',
      },
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
      top + 18
    );

    const dCx = leftX + leftW / 2;
    const dCy = top + 146;
    const dRadius = 74;
    let angle = -Math.PI / 2;

    const nonZero = statusSlices.filter((s) => s.value > 0);
    if (nonZero.length === 0) {
      ctx.beginPath();
      ctx.arc(dCx, dCy, dRadius, 0, Math.PI * 2);
      ctx.strokeStyle = '#E5E7EB';
      ctx.lineWidth = 24;
      ctx.stroke();
    } else {
      for (const slice of nonZero) {
        const sweep = (slice.value / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(dCx, dCy, dRadius, angle, angle + sweep);
        ctx.strokeStyle = slice.color;
        ctx.lineWidth = 24;
        ctx.stroke();
        angle += sweep;
      }
    }

    // Center total count
    ctx.direction = 'ltr';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#111827';
    ctx.font = `800 26px ${this.fontMono}`;
    ctx.fillText(`${stats.totalChecks}`, dCx, dCy - 6);
    ctx.fillStyle = '#6B7280';
    ctx.font = `600 12px ${this.fontSans}`;
    ctx.fillText(this.lang === 'ar' ? 'فحص' : 'CHECKS', dCx, dCy + 18);

    // Legend 2x2 grid below donut
    ctx.textBaseline = 'top';
    statusSlices.forEach((s, idx) => {
      const col = idx % 2;
      const row = Math.floor(idx / 2);
      const colW = (leftW - 44) / 2;
      const lx = leftX + 22 + col * colW;
      const ly = top + 252 + row * 56;
      const pct = Math.round((s.value / total) * 100);

      const boxX = this.isRtl ? lx + colW - 14 : lx;
      ctx.fillStyle = s.color;
      ctx.fillRect(boxX, ly + 4, 12, 12);

      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const labelPos = this.isRtl ? boxX - 8 : lx + 20;
      ctx.fillStyle = '#374151';
      ctx.font = `700 14px ${this.fontSans}`;
      ctx.fillText(`${s.label}`, labelPos, ly);
      ctx.direction = 'ltr';
      ctx.fillStyle = '#6B7280';
      ctx.font = `600 13px ${this.fontMono}`;
      ctx.fillText(`${s.value} (${pct}%)`, labelPos, ly + 21);
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
      top + 18
    );

    const topSections = [...this.report.sections]
      .sort((a, b) => {
        const aF = this.report.findings.filter((f) => f.section === a.id && f.status === 'failed').length;
        const bF = this.report.findings.filter((f) => f.section === b.id && f.status === 'failed').length;
        return bF - aF;
      })
      .slice(0, 7);

    let ry = top + 60;
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

      const barTop = ry + 20;
      ctx.fillStyle = '#F3F4F6';
      ctx.fillRect(rightX + 22, barTop, barTotalW, 12);

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
          ctx.fillRect(bx, barTop, w, 12);
          bx += w;
        }
      }
      ry += 44;
    }

    ctx.restore();
    this.y = top + boxH + 26;
  }

  public drawSectionTitle(title: string): boolean {
    if (!this.ensureSpace(64)) return false;
    const ctx = this.ctx;
    ctx.save();
    ctx.textBaseline = 'top';
    ctx.direction = this.isRtl ? 'rtl' : 'ltr';
    ctx.textAlign = this.isRtl ? 'right' : 'left';
    const x = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;
    ctx.fillStyle = '#111827';
    ctx.font = `800 22px ${this.fontSans}`;
    ctx.fillText(title, x, this.y);
    ctx.fillStyle = '#FF263F';
    ctx.fillRect(this.isRtl ? A4_WIDTH_PX - MARGIN_X - 72 : MARGIN_X, this.y + 30, 72, 3);
    ctx.fillStyle = '#E5E7EB';
    ctx.fillRect(MARGIN_X, this.y + 33, CONTENT_WIDTH, 1.2);
    ctx.restore();
    this.y += 48;
    return true;
  }

  public drawKeyValueBlock(rows: { label: string; value: string; accent?: string }[]): void {
    const ctx = this.ctx;
    for (const row of rows) {
      if (this.pageLimitReached) return;
      ctx.font = `500 17px ${this.fontSans}`;
      const valLines = wrapTextLines(ctx, row.value, CONTENT_WIDTH - 28);
      const needed = 30 + valLines.length * 24 + 14;
      if (!this.ensureSpace(needed)) return;

      ctx.save();
      ctx.textBaseline = 'top';
      ctx.direction = this.isRtl ? 'rtl' : 'ltr';
      ctx.textAlign = this.isRtl ? 'right' : 'left';
      const x = this.isRtl ? A4_WIDTH_PX - MARGIN_X : MARGIN_X;

      ctx.fillStyle = row.accent || '#374151';
      ctx.font = `700 17px ${this.fontSans}`;
      ctx.fillText(row.label, x, this.y);
      this.y += 26;

      ctx.fillStyle = '#111827';
      ctx.font = `500 16.5px ${this.fontSans}`;
      for (const ln of valLines) {
        ctx.fillText(ln, x, this.y);
        this.y += 24;
      }
      ctx.restore();
      this.y += 10;
    }
    this.y += 8;
  }

  public drawBulletList(items: string[], bulletColor = '#FF263F'): void {
    const ctx = this.ctx;
    for (const item of items) {
      if (this.pageLimitReached) return;
      ctx.font = `500 16.5px ${this.fontSans}`;
      const lines = wrapTextLines(ctx, item, CONTENT_WIDTH - 32);
      const needed = lines.length * 24 + 10;
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
      ctx.font = `500 16.5px ${this.fontSans}`;
      for (const ln of lines) {
        ctx.fillText(ln, textX, this.y);
        this.y += 24;
      }
      ctx.restore();
      this.y += 8;
    }
    this.y += 8;
  }

  public drawScreenshotBlock(img: HTMLImageElement | null): void {
    if (!img || !img.naturalWidth || this.pageLimitReached) return;
    const maxW = CONTENT_WIDTH;
    const maxH = 380;
    const aspect = img.naturalWidth / Math.max(1, img.naturalHeight);
    let drawW = maxW;
    let drawH = drawW / aspect;
    if (drawH > maxH) {
      drawH = maxH;
      drawW = drawH * aspect;
    }
    if (!this.ensureSpace(drawH + 34)) return;

    const x = MARGIN_X + Math.round((CONTENT_WIDTH - drawW) / 2);
    const ctx = this.ctx;
    ctx.save();
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 1.5;
    ctx.drawImage(img, x, this.y, drawW, drawH);
    ctx.strokeRect(x, this.y, drawW, drawH);
    ctx.restore();
    this.y += drawH + 26;
  }

  public finalizeToPdf(): void {
    const pagesToExport = this.pages.slice(0, MAX_PDF_PAGES);
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

  const [logoImg, screenshotImg] = await Promise.all([
    loadImageElement(OFFICIAL_BRAND_ASSETS.lightLogo),
    report.screenshot?.imageDataUrl
      ? loadImageElement(report.screenshot.imageDataUrl)
      : Promise.resolve(null),
  ]);

  const doc = new WhitePageComposer(report, lang, logoImg);
  const isAr = lang === 'ar';

  // Page 1: Cover Header (separated Logo & Stamp) + Executive Summary + Classification Scale Diagram
  doc.drawCoverHeader();
  doc.drawExecutiveSummary();
  doc.drawClassificationLevelDiagram();

  // Visual Analytics Charts (Status Donut & Sections Health Bars)
  doc.drawAnalyticsCharts();

  // 1. Five Separated Security Pillars
  if (!doc.isFull() && report.separatedAssessments) {
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

  // 2. Domain Authenticity & Subdomain CNAME Audit
  if (!doc.isFull() && report.domainAuthenticity) {
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

  // 3. Key Factors & Score Breakdown
  if (!doc.isFull() && report.topReasons && report.topReasons.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr ? '٣. أبرز الأسباب المؤثرة في التقييم' : '3. Key Factors Driving This Verdict'
      )
    ) {
      doc.drawBulletList(report.topReasons.map((r) => r[lang]));
    }
  }

  if (!doc.isFull() && report.scoreBreakdown && report.scoreBreakdown.length > 0) {
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

  // 5. Evidence Buckets
  if (!doc.isFull() && report.evidenceBuckets) {
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

  // 6. Deep HTML & JavaScript Source Forensics + Discovered Site Subdomains
  if (!doc.isFull() && report.sourceIntel) {
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

  // 7. Redirect Chain, DNS & SSL/TLS Telemetry
  if (!doc.isFull()) {
    if (
      doc.drawSectionTitle(
        isAr
          ? '٧. سلسلة إعادة التوجيه وDNS وشهادة التشفير'
          : '7. Redirect Chain, DNS & SSL/TLS Certificate Telemetry'
      )
    ) {
      if (report.redirects.length > 0) {
        doc.drawBulletList(
          report.redirects.map((h) =>
            isAr
              ? `قفزة #${h.step} [${h.redirectType || 'http'} · HTTP ${h.statusCode ?? 'خطأ'}] -> ${h.url} (${h.latencyMs}ms${h.downgradedToHttp ? ' · خفض إلى HTTP غير مشفر!' : ''})`
              : `Hop #${h.step} [${h.redirectType || 'http'} · HTTP ${h.statusCode ?? 'ERR'}] -> ${h.url} (${h.latencyMs}ms${h.downgradedToHttp ? ' · HTTPS->HTTP!' : ''})`
          ),
          '#0284C7'
        );
      }
      const infraRows: { label: string; value: string }[] = [];
      if (report.domainIntel) {
        const di = report.domainIntel;
        infraRows.push({
          label: isAr ? 'بيانات النطاق وسجلات DNS' : 'Domain & DNS Resolution',
          value: isAr
            ? `النطاق: ${di.registrableDomain} · العمر الإرشادي: ${di.domainAgeDays ?? 'غير متوفر'} يوماً · IP: ${di.ipAddress || 'غير متوفر'} (${di.asn || 'غير متوفر'}) · CNAME: ${di.dnsRecords.cname?.join(', ') || 'لا يوجد'} · CAA: ${di.dnsRecords.caa?.join(', ') || 'لا يوجد'} · DNSSEC: ${di.dnsRecords.dnssecValidated === true ? 'مفعّل' : 'غير مفعّل/غير معروف'}`
            : `Domain: ${di.registrableDomain} · Age: ${di.domainAgeDays ?? 'Unknown'}d · IP: ${di.ipAddress || 'N/A'} (${di.asn || 'N/A'}) · CNAME: ${di.dnsRecords.cname?.join(', ') || 'None'} · CAA: ${di.dnsRecords.caa?.join(', ') || 'None'} · DNSSEC: ${di.dnsRecords.dnssecValidated === true ? 'Validated' : 'Unsigned/Unknown'}`,
        });
      }
      if (report.tlsIntel) {
        const t = report.tlsIntel;
        infraRows.push({
          label: isAr ? 'شهادة التشفير SSL/TLS' : 'SSL/TLS Certificate',
          value: isAr
            ? `HTTPS: ${t.httpsAvailable ? 'متاح' : 'غير متاح'} · موثوقة: ${t.authorized ? 'نعم' : 'لا'} · البروتوكول: ${t.protocol || 'غير متاح'} · المُصدِر: ${t.issuer || 'غير متاح'} · الانتهاء: ${t.validTo?.slice(0, 10) || 'غير متاح'}${t.sharedWildcardSanNote ? ` · ${t.sharedWildcardSanNote}` : ''}`
            : `HTTPS: ${t.httpsAvailable ? 'Yes' : 'No'} · Trusted: ${t.authorized ? 'Yes' : 'No'} · Protocol: ${t.protocol || 'N/A'} · Issuer: ${t.issuer || 'N/A'} · Expires: ${t.validTo?.slice(0, 10) || 'N/A'}${t.sharedWildcardSanNote ? ` · ${t.sharedWildcardSanNote}` : ''}`,
        });
      }
      if (infraRows.length > 0) doc.drawKeyValueBlock(infraRows);
    }
  }

  // 8. 12-Item SM Website Intelligence Report
  if (!doc.isFull() && report.websiteIntelligenceReport && report.websiteIntelligenceReport.length > 0) {
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

  // 9. Multi-Page Discovery (if inspected pages exist)
  if (!doc.isFull() && report.pageDiscovery && report.pageDiscovery.pages.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr
          ? '٩. استكشاف وفحص الصفحات الداخلية للموقع'
          : '9. Multi-Page Website Discovery & Inspection'
      )
    ) {
      doc.drawBulletList(
        report.pageDiscovery.pages.slice(0, 12).map((pg) =>
          isAr
            ? `${pg.url} [${pg.pageType}] — ${pg.reason.ar}`
            : `${pg.url} [${pg.pageType}] — ${pg.reason.en}`
        ),
        '#0284C7'
      );
    }
  }

  // 10. External Threat Intelligence Feeds
  if (!doc.isFull() && report.threatProviders.length > 0) {
    if (
      doc.drawSectionTitle(
        isAr ? '١٠. مزودو استخبارات التهديدات الخارجية' : '10. External Threat Intelligence Feeds'
      )
    ) {
      doc.drawBulletList(
        report.threatProviders.map((p) =>
          isAr
            ? `${p.providerName} — ${tOperationalState(p.operationalState, lang)} / ${p.status} [نطاق المطابقة: ${p.matchScope || 'لا يوجد'}]: ${p.verdictDetail.ar}`
            : `${p.providerName} — ${tOperationalState(p.operationalState, lang)} / ${p.status} [Scope: ${p.matchScope || 'none'}]: ${p.verdictDetail.en}`
        ),
        '#374151'
      );
    }
  }

  // 11. Screenshot Visual Evidence (when available)
  if (!doc.isFull() && screenshotImg) {
    if (
      doc.drawSectionTitle(
        isAr ? '١١. المعاينة البصرية المعزولة للموقع' : '11. Isolated Visual Website Preview'
      )
    ) {
      doc.drawScreenshotBlock(screenshotImg);
    }
  }

  // 12. Comprehensive Technical Findings (up to 12 pages max)
  if (!doc.isFull()) {
    const orderedFindings = [
      ...report.findings.filter((f) => f.status === 'failed'),
      ...report.findings.filter((f) => f.status === 'warning'),
      ...report.findings.filter((f) => f.status === 'unknown'),
      ...report.findings.filter((f) => f.status === 'pass'),
    ];
    if (orderedFindings.length > 0) {
      if (
        doc.drawSectionTitle(
          isAr
            ? '١٢. السجل الكامل لنتائج الفحص والأدلة والتوصيات'
            : '12. Detailed Findings, Forensic Evidence & Guidance'
        )
      ) {
        doc.drawKeyValueBlock(
          orderedFindings.map((f) => ({
            label: `${f.test[lang]} — ${tStatus(f.status, lang)} (${tSeverity(f.severity, lang)})`,
            value: isAr
              ? `النتيجة: ${f.result.ar} · التفسير: ${f.explanation.ar} · الدليل: ${f.evidence}`
              : `Result: ${f.result.en} · Analysis: ${f.explanation.en} · Evidence: ${f.evidence}`,
            accent: f.status === 'failed' ? '#DC2626' : f.status === 'warning' ? '#D97706' : '#16A34A',
          }))
        );
      }
    }
  }

  doc.finalizeToPdf();
}
