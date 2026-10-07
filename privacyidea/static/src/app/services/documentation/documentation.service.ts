/**
 * (c) NetKnights GmbH 2026,  https://netknights.it
 *
 * This code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 **/
import { inject, Injectable } from "@angular/core";
import { ConfigService, ConfigServiceInterface } from "@services/config/config.service";

export interface ActionDocumentation {
  info: string[];
  notes: string[];
}

export interface DocumentationServiceInterface {
  openDocumentation(page: string): Promise<void>;

  getVersionUrl(pageUrl: string): string;

  getFallbackUrl(pageUrl: string): string;

  checkFullUrl(url: string): Promise<boolean>;

  checkPageUrl(pageUrl: string): Promise<string | false>;

  openDocumentationPage(page: string): Promise<boolean>;

  /**
   * Based on the selected policy action and its scope,
   * fetches the corresponding documentation HTML page and extracts
   * the relevant section for the selected policy action.
   * @param scope The policy scope (e.g., 'user', 'admin')
   * @param actionName The name of the action (e.g., 'set_pin')
   */
  getPolicyActionDocumentation(scope: string, actionName: string): Promise<ActionDocumentation | null>;
}

@Injectable()
export class DocumentationService implements DocumentationServiceInterface {
  private readonly _configService: ConfigServiceInterface = inject(ConfigService);

  /**
   * The address of our own product documentation (the AMITRONIC knowledge base), provided by the
   * server in the app config (``documentation_url``) exactly like the logo and the page title. It
   * is not baked into the console, so one build serves any deployment and an admin can point it at
   * another address without a rebuild. An empty value means there is no documentation to open and
   * every help entry point stays inert.
   */
  private get _baseUrl(): string {
    return this._configService.config().documentation_url || "";
  }

  /**
   * Open our product documentation. The knowledge base is a single live site with its own
   * navigation and search; it has no per-console-route pages, so the console route is deliberately
   * not turned into a deep link (that would open a non-existent page). When a deployment publishes
   * per-page documentation at the configured address, use :meth:`openDocumentationPage`.
   */
  openDocumentation(_: string): Promise<void> {
    const baseUrl = this._baseUrl;
    if (!baseUrl) {
      return Promise.resolve();
    }
    window.open(baseUrl, "_blank");
    return Promise.resolve();
  }

  /**
   * Compose the URL of a page within the documentation tree at the configured address.
   */
  getVersionUrl(pageUrl: string): string {
    const baseUrl = this._baseUrl;
    if (!baseUrl) {
      return "";
    }
    pageUrl = pageUrl.replace(/^\/+/, ""); // Remove leading slashes
    return `${baseUrl}${pageUrl}`;
  }

  /**
   * Our documentation is one live tree, not a versioned/stable pair like the vendor's readthedocs;
   * the fallback address is therefore the same page as the primary one.
   */
  getFallbackUrl(pageUrl: string): string {
    return this.getVersionUrl(pageUrl);
  }

  /**
   * * @param url The full URL to check (including base URL and page URL)
   * * Checks if the documentation page exists by fetching and parsing the HTML content.
   * * @returns A promise that resolves to true if the page exists, false otherwise.
   */
  async checkFullUrl(url: string): Promise<boolean> {
    if (!url) {
      return false;
    }
    try {
      const response = await fetch(url);
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      return !doc.querySelector("div.document div.documentwrapper div.bodywrapper div.body h1#notfound");
    } catch (error) {
      console.error("Error checking the page:", error);
      return false;
    }
  }

  /**
   *
   * @param pageUrl The page URL to check (relative to the documentation base URL)
   *  * Checks if the documentation page exists at the configured address.
   *  * Alerts the user if the page is not found.
   *
   * @returns A promise that resolves to the found URL or false if not found.
   */
  async checkPageUrl(pageUrl: string): Promise<string | false> {
    const versionUrl = this.getVersionUrl(pageUrl);
    if (await this.checkFullUrl(versionUrl)) {
      return versionUrl;
    }
    const fallbackUrl = this.getFallbackUrl(pageUrl);
    if (await this.checkFullUrl(fallbackUrl)) {
      return fallbackUrl;
    }
    alert("The documentation page is currently not available.");
    return false;
  }

  async openDocumentationPage(page: string): Promise<boolean> {
    const baseUrl = this._baseUrl;
    if (!baseUrl) {
      return false;
    }
    // First check the page and when found open it
    const versionUrl = this.getVersionUrl(page);
    if (await this.checkFullUrl(versionUrl)) {
      window.open(versionUrl, "_blank");
      return true;
    }
    const fallbackUrl = this.getFallbackUrl(page);
    if (await this.checkFullUrl(fallbackUrl)) {
      window.open(fallbackUrl, "_blank");
      return true;
    }
    alert("The documentation page is currently not available.");
    return false;
  }

  async getPolicyActionDocumentation(scope: string, actionName: string): Promise<ActionDocumentation | null> {
    if (!scope || !actionName || !this._baseUrl) {
      return null;
    }
    // The policy hint is built from a per-scope page (``policies/<scope>.html``) with one section
    // per action. Our knowledge base publishes no such page, so there is nothing to show; the
    // console falls back to the server-provided action description rather than a fabricated hint.
    const page = `policies/${scope}.html`;
    const docUrl = await this._getValidDocUrl(page);
    if (!docUrl) {
      return null;
    }
    try {
      const response = await fetch(docUrl);
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      const sectionId = actionName.replaceAll("_", "-").toLowerCase();
      const section = doc.getElementById(sectionId);
      if (!section) {
        return null;
      }
      const info: string[] = [];
      const notes: string[] = [];
      section.childNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const element = node as HTMLElement;
          if (element.tagName.toLowerCase() === "p") {
            if (!element.textContent?.startsWith("type:")) {
              info.push(element.outerHTML);
            }
          } else if (
            element.tagName.toLowerCase() === "div" &&
            element.classList.contains("admonition") &&
            element.classList.contains("note")
          ) {
            const title = element.querySelector("p.admonition-title");
            if (title) {
              element.removeChild(title);
            }
            notes.push(element.outerHTML);
          }
        }
      });

      return { info, notes };
    } catch (error) {
      console.error("Error fetching or parsing policy action documentation:", error);
      return null;
    }
  }

  private async _getValidDocUrl(pageUrl: string): Promise<string | null> {
    const versionUrl = this.getVersionUrl(pageUrl);
    if (await this.checkFullUrl(versionUrl)) {
      return versionUrl;
    }
    const fallbackUrl = this.getFallbackUrl(pageUrl);
    if (await this.checkFullUrl(fallbackUrl)) {
      return fallbackUrl;
    }
    return null;
  }
}
