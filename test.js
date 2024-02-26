// Import testing utilities
import supertest from "supertest";
import { expect } from "chai";
import server from "../Backend/Server.js";

const apiRequest = supertest(server);

describe("JWKS Server Testing Suite", () => {
    let currentKid;

    it("retrieves JWKS with unexpired keys", async () => {
        const res = await apiRequest.get("/jwks");
        expect(res.status).to.equal(200);
        expect(res.body).to.have.property("keys").that.is.an("array");

        currentKid = res.body.keys[0].kid;
        expect(currentKid).to.be.a("string");
    });

    it("generates a JWT using a valid kid from /jwks", async () => {
        const res = await apiRequest.post(`/auth?kid=${currentKid}`);
        expect(res.status).to.equal(200);
        expect(res.body).to.have.property("token").that.is.a("string");
    });

    it("returns error for non-existent kid in auth endpoint", async () => {
        const fakeKid = "nonexistent-kid";
        const res = await apiRequest.post(`/auth?kid=${fakeKid}`);
        expect(res.status).to.equal(404);
        expect(res.body).to.have.property("error").that.equals("Key not found");
    });
});
