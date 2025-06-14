# Frontend Development Prompts for Lovable.dev AI

This document provides detailed prompts for developing the frontend of the 'It's Just Us' family platform, focusing on theming, UI enhancements, and analytics integration. The backend provides significant support for these features, which should be leveraged.

## Backend Context for Theming:

The application backend supports a seasonal theming system managed via an admin API (`/api/admin/themes`). Themes are stored in the `seasonal_themes` D1 database table with the following key structure for frontend consumption:

*   `name` (TEXT UNIQUE): e.g., 'Juneteenth', 'FathersDay'
*   `description` (TEXT)
*   `start_date`, `end_date` (DATE): For automated activation (frontend/backend might check this).
*   `theme_config_json` (TEXT): A JSON string containing specific configuration details for the frontend to apply the theme. The backend will serve this JSON for the currently active theme.
*   `is_active` (BOOLEAN): Indicates if a theme should be currently applied.

**Example `theme_config_json` structure (from `master_seed_data.sql`):**
```json
// For Juneteenth
{
  "primaryColor": "#AA0000",
  "secondaryColor": "#006A35",
  "accentColor": "#000000",
  "textColor": "#FFFFFF",
  "fontFamily": "Georgia, serif",
  "bannerImageUrl": "/assets/themes/juneteenth/banner.jpg",
  "loadingScreen": {
    "backgroundColor": "#000000",
    "text": "Celebrating Freedom...",
    "icon": "/assets/themes/juneteenth/icon.png"
  }
}

// For Father's Day
{
  "primaryColor": "#1034A6",
  "secondaryColor": "#B0C4DE",
  "accentColor": "#708090",
  "textColor": "#333333",
  "fontFamily": "Verdana, sans-serif",
  "bannerImageUrl": "/assets/themes/fathersday/banner.jpg",
  "loadingScreen": {
    "backgroundColor": "#B0C4DE",
    "text": "Happy Father's Day!",
    "icon": "/assets/themes/fathersday/icon.png"
  }
}
```
The frontend will need to:
1.  Fetch the currently active theme's `theme_config_json` (e.g., from a general app configuration endpoint that provides this).
2.  Parse this JSON and dynamically apply the styles (colors, fonts, images) throughout the application.
3.  Implement logic for custom loading screens based on this configuration.

---

## Prompt 1: Comprehensive Theming System & Holiday Implementations (Juneteenth, Father's Day)

**Objective:** Implement a dynamic theming system and create specific themes for Juneteenth and Father's Day, ensuring a unique, cohesive, and animated user experience across all pages.

**Key Tasks:**

1.  **Develop Frontend Theming Engine:**
    *   Create a robust mechanism (e.g., React Context, CSS variables, styled-components theming provider) to dynamically apply theme styles based on the `theme_config_json` fetched from the backend.
    *   Ensure that all components and pages correctly inherit and apply these theme settings (colors, fonts, text styles).
    *   Implement a default/fallback theme if no seasonal theme is active or if a theme's configuration is incomplete or missing.

2.  **Implement Juneteenth Theme:**
    *   **Visuals & Styling:** Based on the `theme_config_json` example for 'Juneteenth' (see Backend Context).
        *   Apply the specified color palette (`primaryColor`, `secondaryColor`, `accentColor`, `textColor`) across the entire application, including headers, footers, buttons, backgrounds, text, and interactive elements.
        *   Use the suggested `fontFamily` (Georgia, serif) or a similar appropriate font.
        *   Integrate the `bannerImageUrl` where applicable (e.g., on the homepage or key landing sections).
    *   **Unique Feel & Animations:**
        *   Incorporate "fun animations" that are respectful and celebratory of the Juneteenth holiday. This could include subtle hover effects, page load animations, or component entrance animations.
        *   Ensure the overall site feel is unique and cohesive with the theme's significance.
    *   **Custom Loading Screen:** Implement the Juneteenth-specific loading screen as defined in its `theme_config_json` (background color, text, icon). This screen should display while initial assets for the theme/page are loading.
    *   **Page Coverage:** Ensure all pages, including public ones (Homepage, Privacy Policy, Support, User Data, Refund) and authenticated user areas, consistently reflect the Juneteenth theme.

3.  **Implement Father's Day Theme:**
    *   **Visuals & Styling:** Based on the `theme_config_json` example for 'FathersDay'.
        *   Apply its distinct color palette, font family (Verdana, sans-serif or similar), and banner image.
    *   **Unique Feel & Animations:** Design animations and interactions that evoke a sense of warmth, appreciation, or family connection appropriate for Father's Day.
    *   **Custom Loading Screen:** Implement the Father's Day specific loading screen.
    *   **Page Coverage:** Ensure full site coverage for this theme.

4.  **Placeholder Holiday Themes:**
    *   For other holidays mentioned in `master_seed_data.sql` (Christmas, New Year's, Independence Day US, etc., which have `theme_config_json='{"status": "upcoming_configuration"}'`), ensure the frontend gracefully handles these by either applying the default theme or displaying a simple, non-themed "Upcoming Holiday" placeholder if the theme is technically "active" but has no real config. The admin backend allows activating these.

---

## Prompt 2: General UI/UX Enhancements (Loading Screens, Page Animations) & Analytics Integration Guidance

**Objective:** Enhance the overall user experience with default loading screens, smooth page transitions, and provide guidance for integrating web analytics.

**Key Tasks:**

1.  **Default/General Loading Screens:**
    *   **Main Site Loading:** Design and implement a generic, visually appealing, and animated loading screen that displays when the main website (its-just-us-frontend) is first loading, before any specific theme or page content is ready.
    *   **Admin Dashboard Loading:** Create a separate, professional, and efficient loading screen specifically for the admin dashboard area. This should convey a sense of control and data processing.
    *   **Customer Portal Loading:** Design a user-friendly loading screen for the customer/user portal (e.g., when accessing profile settings, billing).
    *   These loading screens should be distinct from the theme-specific loading screens and used when a seasonal theme isn't providing its own.

2.  **Page Transition Animations:**
    *   Implement subtle, performant, and professional animations for transitions between different pages/views within the React single-page application (SPA).
    *   Examples: Fade-ins/outs, slide transitions, or material design motion principles.
    *   Ensure these animations enhance the user experience without being distracting or causing performance issues.

3.  **Guidance for Analytics Integration (for Frontend Developer):**
    *   **Google Analytics (GA4):**
        *   Provide instructions on how to integrate the Google Analytics (GA4) tracking script into the React application. This typically involves:
            *   Adding the `gtag.js` snippet to the `public/index.html` head or using a React-specific library (e.g., `react-ga4`).
            *   Initializing GA4 with the measurement ID.
            *   Implementing page view tracking that correctly fires on client-side route changes (e.g., by hooking into the `react-router-dom` history listener).
    *   **Google Search Console:**
        *   Explain the common methods for site verification with Google Search Console:
            *   Adding a specific HTML meta tag to the homepage's `<head>`.
            *   Uploading an HTML file to the root directory of the site (requires access to the build output's static assets).
        *   (Note: This prompt is for *guidance* on how a frontend developer would do this, not for the AI to implement directly as it requires external account setup and DNS/file access usually.)

---

**General Instructions for AI:**
*   Ensure all designs are responsive and mobile-first.
*   Prioritize performance and accessibility (WCAG AA where possible).
*   The frontend is a React application (`its-just-us-frontend/`). Use modern React practices (hooks, context, etc.).
*   Assume necessary assets (images, icons specified in theme configs) will be placed in the `public/assets/themes/` directory structure (e.g., `public/assets/themes/juneteenth/banner.jpg`).

```
