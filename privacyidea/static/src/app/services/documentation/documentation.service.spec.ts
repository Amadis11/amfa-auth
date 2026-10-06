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
import { provideHttpClient } from "@angular/common/http";
import { provideHttpClientTesting } from "@angular/common/http/testing";
import { TestBed } from "@angular/core/testing";
import { ConfigService } from "@services/config/config.service";
import { MockConfigService } from "@testing/mock-services/mock-config-service";
import { DocumentationService } from "./documentation.service";

describe("DocumentationService", () => {
  let service: DocumentationService;
  let configService: MockConfigService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        DocumentationService,
        { provide: ConfigService, useClass: MockConfigService }
      ]
    });
    service = TestBed.inject(DocumentationService);
    configService = TestBed.inject(ConfigService) as unknown as MockConfigService;
  });

  it("should be created", () => {
    expect(service).toBeTruthy();
  });

  it("does nothing while no documentation address is configured", async () => {
    const windowOpenSpy = jest.spyOn(window, "open").mockImplementation(() => null);
    await service.openDocumentation("tokens");
    expect(windowOpenSpy).not.toHaveBeenCalled();
    expect(service.getVersionUrl("some/page.html")).toBe("");
    windowOpenSpy.mockRestore();
  });

  it("builds page URLs from the configured address", () => {
    configService.config.set({ ...configService.config(), documentation_url: "https://docs.example/" });
    expect(service.getVersionUrl("some/page.html")).toBe("https://docs.example/some/page.html");
    // One live tree, so the fallback is the same page.
    expect(service.getFallbackUrl("some/page.html")).toBe("https://docs.example/some/page.html");
  });

  it("opens the configured documentation root", async () => {
    configService.config.set({ ...configService.config(), documentation_url: "https://docs.example/" });
    const windowOpenSpy = jest.spyOn(window, "open").mockImplementation(() => null);
    await service.openDocumentation("tokens");
    expect(windowOpenSpy).toHaveBeenCalledWith("https://docs.example/", "_blank");
    windowOpenSpy.mockRestore();
  });

  it("opens a documentation page that exists", async () => {
    configService.config.set({ ...configService.config(), documentation_url: "https://docs.example/" });
    const windowOpenSpy = jest.spyOn(window, "open").mockImplementation(() => null);
    const checkFullUrlSpy = jest.spyOn(service, "checkFullUrl").mockResolvedValue(true);
    const opened = await service.openDocumentationPage("guide.html");
    expect(opened).toBe(true);
    expect(windowOpenSpy).toHaveBeenCalledWith("https://docs.example/guide.html", "_blank");
    windowOpenSpy.mockRestore();
    checkFullUrlSpy.mockRestore();
  });

  it("shows no policy hint while no documentation address is configured", async () => {
    expect(await service.getPolicyActionDocumentation("admin", "set_pin")).toBeNull();
  });
});
