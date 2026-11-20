export const OFFICIAL_BRAND_ASSETS = {
  // Used strictly as the browser favicon & PWA app icon (never placed inside pages)
  siteIcon: '/assets/aistudio/IMG_20261121_014405_471_cf6918d1.jpg',
  // Official logos: darkLogo on pure black (#000000) page, lightLogo on pure white (#FFFFFF) page
  darkLogo: '/assets/aistudio/file_00000000a358824689befab2c537ed47_89a51d34.png',
  lightLogo: '/assets/aistudio/file_00000000d8948246a4b06b393e227b25_b9edba8d.png',
} as const;

interface BrandMarkProps {
  forceTheme?: 'dark' | 'light';
  className?: string;
}

/**
 * Renders the official Scan Link SM logo directly without borders, frames, or padding boxes.
 * - White/Light mode page -> White background logo
 * - Black/Dark mode page  -> Black background logo
 */
export function BrandMark({ forceTheme, className = 'h-9 w-auto' }: BrandMarkProps) {
  if (forceTheme === 'dark') {
    return (
      <img
        src={OFFICIAL_BRAND_ASSETS.darkLogo}
        alt="Scan Link SM"
        className={`object-contain shrink-0 select-none ${className}`}
      />
    );
  }

  if (forceTheme === 'light') {
    return (
      <img
        src={OFFICIAL_BRAND_ASSETS.lightLogo}
        alt="Scan Link SM"
        className={`object-contain shrink-0 select-none ${className}`}
      />
    );
  }

  return (
    <>
      <img
        src={OFFICIAL_BRAND_ASSETS.lightLogo}
        alt="Scan Link SM"
        className={`object-contain shrink-0 select-none dark:hidden ${className}`}
      />
      <img
        src={OFFICIAL_BRAND_ASSETS.darkLogo}
        alt="Scan Link SM"
        className={`object-contain shrink-0 select-none hidden dark:block ${className}`}
      />
    </>
  );
}
