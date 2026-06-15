import Variants from "../../src/handlers/variant";
import type { VariantContext } from "../../src/handlers/variant";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

const makeOkResponse = (body: unknown) => ({
    ok: true,
    status: 200,
    json: async () => body,
} as Response);

const makeErrorResponse = (status: number, body: Record<string, string> = { error: "request failed" }) => ({
    ok: false,
    status,
    json: async () => body,
} as Response);

const sampleContext: VariantContext = {
    variant_id: "uuid-abc",
    deployment_environment: "embedded Linux on STM32MP25",
    platform: "yocto",
    objectives_profile: "default",
    notes: "runtime only",
};

describe("Variants.getContext", () => {
    it("returns VariantContext on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse(sampleContext));
        const ctx = await Variants.getContext("uuid-abc");
        expect(ctx.variant_id).toBe("uuid-abc");
        expect(ctx.platform).toBe("yocto");
        expect(ctx.notes).toBe("runtime only");
    });

    it("sends GET to correct URL", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse(sampleContext));
        await Variants.getContext("uuid-abc");
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/variants/uuid-abc/context"),
            expect.objectContaining({ mode: "cors" }),
        );
    });

    it("throws on non-200 response", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(404, { error: "Variant not found." }));
        await expect(Variants.getContext("uuid-abc")).rejects.toThrow("Variant not found.");
    });

    it("throws generic message when error body is unparseable", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => { throw new Error("not json"); },
        } as unknown as Response);
        await expect(Variants.getContext("uuid-abc")).rejects.toThrow("Get context failed (500)");
    });
});

describe("Variants.updateContext", () => {
    it("returns updated VariantContext on 200", async () => {
        const updated: VariantContext = { ...sampleContext, platform: "npm" };
        mockFetch.mockResolvedValueOnce(makeOkResponse(updated));
        const ctx = await Variants.updateContext("uuid-abc", { platform: "npm" });
        expect(ctx.platform).toBe("npm");
    });

    it("sends PUT with correct body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse(sampleContext));
        await Variants.updateContext("uuid-abc", { platform: "yocto", notes: "runtime only" });
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/variants/uuid-abc/context"),
            expect.objectContaining({
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ platform: "yocto", notes: "runtime only" }),
            }),
        );
    });

    it("throws with API error message on non-200", async () => {
        mockFetch.mockResolvedValueOnce(
            makeErrorResponse(400, { error: "Unknown context fields: ['bad']" })
        );
        await expect(Variants.updateContext("uuid-abc", {})).rejects.toThrow("Unknown context fields");
    });

    it("throws generic message when error body is unparseable", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => { throw new Error("not json"); },
        } as unknown as Response);
        await expect(Variants.updateContext("uuid-abc", {})).rejects.toThrow("Update context failed (500)");
    });
});
