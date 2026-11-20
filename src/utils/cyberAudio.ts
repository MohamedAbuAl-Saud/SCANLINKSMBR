/**
 * Scan Link SM - Synthesized Web Audio Effects Engine
 * Pure code synthesis with zero external audio assets, zero latency, and offline support.
 */

const SOUND_STORAGE_KEY = 'scanlink_sound_enabled';

class CyberAudioManager {
  private ctx: AudioContext | null = null;
  private enabled: boolean = true;

  constructor() {
    try {
      const stored = localStorage.getItem(SOUND_STORAGE_KEY);
      this.enabled = stored !== null ? stored === 'true' : true;
    } catch {
      this.enabled = true;
    }
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public toggle(): boolean {
    this.enabled = !this.enabled;
    try {
      localStorage.setItem(SOUND_STORAGE_KEY, String(this.enabled));
    } catch {
      // ignore
    }
    if (this.enabled) {
      this.playBlip(720, 0.04);
    }
    return this.enabled;
  }

  private initCtx(): AudioContext | null {
    if (!this.enabled) return null;
    try {
      if (!this.ctx) {
        const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        if (AudioCtx) {
          this.ctx = new AudioCtx();
        }
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume().catch(() => {});
      }
      return this.ctx;
    } catch {
      return null;
    }
  }

  /**
   * Micro-interaction click blip
   */
  public playClick(): void {
    this.playBlip(980, 0.03, 0.04);
  }

  /**
   * Scan start cyber pulse
   */
  public playScanStart(): void {
    const ctx = this.initCtx();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;

      // Primary oscillator ramp
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(420, now);
      osc.frequency.exponentialRampToValueAtTime(840, now + 0.18);

      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + 0.22);

      // Sub-pulse tone
      const subOsc = ctx.createOscillator();
      const subGain = ctx.createGain();
      subOsc.type = 'triangle';
      subOsc.frequency.setValueAtTime(210, now + 0.05);
      subOsc.frequency.exponentialRampToValueAtTime(420, now + 0.25);

      subGain.gain.setValueAtTime(0.04, now + 0.05);
      subGain.gain.exponentialRampToValueAtTime(0.001, now + 0.28);

      subOsc.connect(subGain);
      subGain.connect(ctx.destination);

      subOsc.start(now + 0.05);
      subOsc.stop(now + 0.28);
    } catch {
      // Audio autoplay policy fallback
    }
  }

  /**
   * Scan complete chime based on threat classification
   */
  public playScanComplete(isThreat: boolean = false): void {
    const ctx = this.initCtx();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;

      if (isThreat) {
        // Cautionary descending double-alert
        [380, 240].forEach((freq, i) => {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          const start = now + i * 0.12;

          osc.type = 'sawtooth';
          osc.frequency.setValueAtTime(freq, start);
          osc.frequency.exponentialRampToValueAtTime(freq * 0.75, start + 0.14);

          gain.gain.setValueAtTime(0.06, start);
          gain.gain.exponentialRampToValueAtTime(0.001, start + 0.16);

          osc.connect(gain);
          gain.connect(ctx.destination);

          osc.start(start);
          osc.stop(start + 0.16);
        });
      } else {
        // Positive ascending triad chime
        [523.25, 659.25, 783.99].forEach((freq, i) => {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          const start = now + i * 0.08;

          osc.type = 'sine';
          osc.frequency.setValueAtTime(freq, start);

          gain.gain.setValueAtTime(0.05, start);
          gain.gain.exponentialRampToValueAtTime(0.001, start + 0.25);

          osc.connect(gain);
          gain.connect(ctx.destination);

          osc.start(start);
          osc.stop(start + 0.25);
        });
      }
    } catch {
      // ignore
    }
  }

  /**
   * Provider status refresh notification chime
   */
  public playRefresh(): void {
    const ctx = this.initCtx();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(540, now);
      osc.frequency.exponentialRampToValueAtTime(720, now + 0.1);

      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.14);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + 0.14);
    } catch {
      // ignore
    }
  }

  private playBlip(freq: number, duration: number, vol: number = 0.03): void {
    const ctx = this.initCtx();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now);

      gain.gain.setValueAtTime(vol, now);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + duration);
    } catch {
      // ignore
    }
  }
}

export const cyberAudio = new CyberAudioManager();
