import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { ld as vcjs } from '@transmute/vc.js';
import { Ed25519Signature2018, Ed25519VerificationKey2018 } from '@transmute/ed25519-signature-2018';
import { PrivateKey } from '@hiero-ledger/sdk';
import { CheckResult } from '@transmute/jsonld-schema';
import { GenerateUUIDv4, ICredentialSubject, IVC, Schema, SignatureType } from '@guardian/interfaces';
import { VcDocument } from './vc-document.js';
import { VpDocument } from './vp-document.js';
import { VcSubject } from './vc-subject.js';
import { TimestampUtils } from '../timestamp-utils.js';
import { DocumentLoaderFunction } from '../document-loader/document-loader-function.js';
import { DocumentLoader } from '../document-loader/document-loader.js';
import { SchemaLoader, SchemaLoaderFunction } from '../document-loader/schema-loader.js';
import { Issuer } from './issuer.js';
import axios from 'axios';
import { BbsBlsSignature2020, BbsBlsSignatureProof2020, Bls12381G2KeyPair, KeyPairOptions } from '@mattrglobal/jsonld-signatures-bbs';
import { IPFS } from '../../helpers/index.js';
import { CommonDidDocument, HederaBBSMethod, HederaDidDocument, HederaEd25519Method } from './did/index.js';

import * as pkg from 'jsonld-signatures';
import { ContextHelper } from './context-helper.js';
const { verify, purposes } = pkg;

/**
 * Suite interface
 */
export interface ISuite {
    /**
     * Issuer
     */
    issuer: string;
    /**
     * Suite
     */
    suite: Ed25519Signature2018;
}

/**
 * Suite options
 */
export interface ISuiteOptions {
    /**
     * Issuer
     */
    did: string;
    /**
     * Private key
     */
    key: string | PrivateKey,
    /**
     * Signature type
     */
    signatureType?: SignatureType;
}

/**
 * Document options
 */
export interface IDocumentOptions {
    /**
     * Group
     */
    group?: {
        /**
         * Group ID
         */
        groupId: string;
        /**
         * Group type
         */
        type: string;
        /**
         * Group context
         */
        context: any;
    };
    /**
     * UUID
     */
    uuid?: string;
    /**
     * Evidence entries to embed in the VC before signing
     */
    evidence?: { type: string[]; dataType: string; data: string }[];
    /**
     * JSON-LD context URL for evidence entries
     */
    evidenceContext?: string;
}

/**
 * Connecting VCJS library
 */
export class VCJS {
    /**
     * Document loaders
     * @private
     */
    private readonly documentLoaders: DocumentLoader[];
    /**
     * Schema loaders
     * @private
     */
    private readonly schemaLoaders: SchemaLoader[];
    /**
     * Schema context
     * @private
     */
    private readonly schemaContext: string[];
    /**
     * Loader
     * @private
     */
    protected loader: DocumentLoaderFunction;
    /**
     * Schema loader
     * @private
     */
    private schemaLoader: SchemaLoaderFunction;

    constructor() {
        this.schemaContext = [];
        this.documentLoaders = [];
        this.schemaLoaders = [];
    }

    /**
     * Add Schema context
     *
     * @param {string} context - context
     *
     */
    public addContext(context: string): void {
        this.schemaContext.push(context);
    }

    /**
     * Add DID or Schema document loader
     *
     * @param {DocumentLoader} documentLoader - Document Loader
     *
     */
    public addDocumentLoader(documentLoader: DocumentLoader): void {
        this.documentLoaders.push(documentLoader);
    }

    /**
     * Build Document Loader
     * Builded loader is used to sign and verify documents
     */
    public buildDocumentLoader(): void {
        this.loader = DocumentLoader.build(this.documentLoaders);
    }

    /**
     * Add Schema loader
     *
     * @param {DocumentLoader} documentLoader - Document Loader
     *
     */
    public addSchemaLoader(schemaLoader: SchemaLoader): void {
        this.schemaLoaders.push(schemaLoader);
    }

    /**
     * Build Schema Loader
     * Builded loader is used to sign and verify documents
     */
    public buildSchemaLoader(): void {
        this.schemaLoader = SchemaLoader.build(this.schemaLoaders);
    }

    /**
     * Generate new UUIDv4
     *
     * @param {IDocumentOptions} documentOptions - Document Options
     */
    protected generateUUID(documentOptions?: IDocumentOptions): string {
        if (documentOptions && documentOptions.uuid) {
            return documentOptions.uuid;
        } else {
            return `urn:uuid:${GenerateUUIDv4()}`;
        }
    }

    /**
     * Verify VC Document
     *
     * @param {any} json - VC Document
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {boolean} - status
     */
    public async verify(json: any, documentLoader: DocumentLoaderFunction): Promise<boolean> {
        let result;
        if (json.proof.type === SignatureType.Ed25519Signature2018) {
            result = await vcjs.verifyVerifiableCredential({
                credential: json,
                suite: [new Ed25519Signature2018()],
                documentLoader,
            });
        } else {
            result = await verify(json, {
                purpose: new purposes.AssertionProofPurpose(),
                suite: [new BbsBlsSignature2020(), new BbsBlsSignatureProof2020()],
                documentLoader,
            });
        }
        if (result.verified) {
            return true;
        } else {
            if (result.results) {
                for (const element of result.results) {
                    if (!element.verified && element.error && element.error.message) {
                        throw new Error(element.error.message);
                    }
                }
            }
            throw new Error('Verification error');
        }
    }

    /**
     * Verify Schema
     *
     * @param {HcsVcDocument<VcSubject>} vcDocument - VC Document
     *
     * @returns {CheckResult} - is verified
     */
    public async verifySchema(vcDocument: VcDocument | any): Promise<CheckResult> {
        let vc: IVC;
        if (vcDocument && typeof vcDocument.toJsonTree === 'function') {
            vc = vcDocument.toJsonTree();
        } else {
            vc = vcDocument;
        }

        if (!vc.credentialSubject) {
            throw new Error('"credentialSubject" property is required.');
        }

        const vcObject = JSON.parse(JSON.stringify(vc));

        const subjects = vcObject.credentialSubject;
        const subject = Array.isArray(subjects) ? subjects[0] : subjects;

        if (!this.schemaLoader) {
            throw new Error('Schema Loader not found');
        }

        const schema = await this.schemaLoader(subject['@context'], subject.type, 'vc');

        if (!schema) {
            throw new Error('Schema not found');
        }

        const ajv = new Ajv({
            loadSchema: this.loadSchema
        });
        addFormats(ajv);

        this.prepareSchema(schema);

        const schemaObject = Schema.fromVc(schema);

        ContextHelper.setContext(subject, schemaObject);

        const validate = await ajv.compileAsync(schema);
        const valid = validate(vcObject);
        const errors = this.enhanceConditionErrors(validate.errors as any[], schema);

        return new CheckResult(valid, 'JSON_SCHEMA_VALIDATION_ERROR', errors as any);
    }

    /**
     * Verify VC Document
     *
     * @param {HcsVcDocument<VcSubject>} vcDocument - VC Document
     *
     * @param loader
     * @returns {Promise<boolean>} - is verified
     */
    public async verifyVC(vcDocument: VcDocument | any, loader?: DocumentLoaderFunction): Promise<boolean> {
        let vc: IVC;
        if (vcDocument && typeof vcDocument.toJsonTree === 'function') {
            vc = vcDocument.toJsonTree();
        } else {
            vc = vcDocument;
        }
        if (!loader) {
            return await this.verify(vc, this.loader);
        } else {
            return await this.verify(vc, loader)
        }
    }

    /**
     * Delete system fields from schema defs
     *
     * @param schema Schema
     */
    private prepareSchema(schema: any) {
        this.stripIfOnly(schema);

        const defsObj = schema.$defs;
        if (!defsObj) {
            return;
        }

        const defsKeys = Object.keys(defsObj);
        for (const key of defsKeys) {
            const nestedSchema = defsObj[key];
            this.stripIfOnly(nestedSchema);
            const required = nestedSchema.required;
            if (!required || required.length === 0) {
                continue;
            }
            nestedSchema.required = required.filter((field: any) => !nestedSchema.properties[field] || !nestedSchema.properties[field].readOnly);
        }

        if (!Array.isArray(schema.allOf)) {
            return;
        }
        const rootProperties = schema.properties || {};
        const conditionalByRef = new Map<string, Set<string>>();
        for (const condEntry of schema.allOf) {
            if (!condEntry?.if) { continue; }
            for (const branch of [condEntry.then, condEntry.else]) {
                if (!branch?.properties) { continue; }
                for (const propKey of Object.keys(branch.properties)) {
                    const constraint = branch.properties[propKey];
                    if (!constraint || typeof constraint !== 'object') { continue; }
                    const ref = rootProperties[propKey]?.$ref;
                    if (!ref || !defsObj[ref]) { continue; }
                    if (!conditionalByRef.has(ref)) { conditionalByRef.set(ref, new Set()); }
                    const conditionalFields = conditionalByRef.get(ref)!;
                    if (Array.isArray(constraint.required)) {
                        for (const fieldName of constraint.required) { conditionalFields.add(fieldName); }
                    }
                    if (constraint.properties) {
                        for (const [fieldName, val] of Object.entries(constraint.properties)) {
                            if (val === false) { conditionalFields.add(fieldName); }
                        }
                    }
                }
            }
        }
        for (const [ref, conditionalFields] of conditionalByRef) {
            const defsEntry = defsObj[ref];
            if (Array.isArray(defsEntry?.required) && conditionalFields.size) {
                defsEntry.required = defsEntry.required.filter((r: string) => !conditionalFields.has(r));
            }
        }
    }

    private stripIfOnly(schema: any) {
        if (!Array.isArray(schema?.allOf)) {
            return;
        }
        schema.allOf = schema.allOf.filter(
            (entry: any) => !entry?.if || entry.then !== undefined || entry.else !== undefined
        );
        if (schema.allOf.length === 0) {
            delete schema.allOf;
        }
    }

    /**
     * Converts the nested JSON Schema `if` node into a readable condition string
     */
    private describeIfCondition(node: any): string {
        if (!node) { return ''; }
        if (Array.isArray(node.anyOf)) {
            return node.anyOf.map((b: any) => this.describeIfCondition(b)).filter(Boolean).join(' OR ');
        }
        if (Array.isArray(node.allOf)) {
            return node.allOf.map((b: any) => this.describeIfCondition(b)).filter(Boolean).join(' AND ');
        }
        if (node.properties) {
            return Object.entries(node.properties as Record<string, any>)
                .map(([key, val]) => this.describeIfConditionLeaf(val, key))
                .filter(Boolean)
                .join(', ');
        }
        return '';
    }

    private describeIfConditionLeaf(node: any, leafKey: string): string {
        if (!node) { return ''; }
        if (node.const !== undefined) {
            return `${leafKey} = '${node.const}'`;
        }
        if (node.properties) {
            return Object.entries(node.properties as Record<string, any>)
                .map(([key, val]) => this.describeIfConditionLeaf(val, key))
                .filter(Boolean)
                .join(', ');
        }
        if (Array.isArray(node.anyOf)) {
            return node.anyOf.map((b: any) => this.describeIfConditionLeaf(b, leafKey)).filter(Boolean).join(' OR ');
        }
        if (Array.isArray(node.allOf)) {
            return node.allOf.map((b: any) => this.describeIfConditionLeaf(b, leafKey)).filter(Boolean).join(' AND ');
        }
        return '';
    }

    /**
     * Replaces AJV messages with a human-readable description
     */
    private enhanceConditionErrors(errors: any[] | null | undefined, schema: any): any[] | null | undefined {
        if (!errors?.length || !Array.isArray(schema?.allOf)) {
            return errors;
        }
        return errors.map(error => {
            if (error.keyword !== 'false schema') { return error; }
            const match = (error.schemaPath as string)?.match(/^#\/allOf\/(\d+)\/(then|else)\//);
            if (!match) { return error; }
            const condEntry = schema.allOf[parseInt(match[1], 10)];
            if (!condEntry?.if) { return error; }
            const fieldName = (error.instancePath as string).split('/').filter(Boolean).pop() || 'field';
            const condition = this.describeIfCondition(condEntry.if) || 'condition not met';
            return {
                ...error,
                message: `Field '${fieldName}' is not allowed unless: ${condition}`,
            };
        });
    }

    /**
     * Verify Subject
     *
     * @param {any} subject - subject
     *
     * @returns {CheckResult} - is verified
     */
    public async verifySubject(subject: any): Promise<CheckResult> {
        if (!this.schemaLoader) {
            throw new Error('Schema Loader not found');
        }

        const schema = await this.schemaLoader(subject['@context'], subject.type, 'subject');

        if (!schema) {
            throw new Error('Schema not found');
        }

        const ajv = new Ajv({
            loadSchema: this.loadSchema
        });
        addFormats(ajv);

        this.prepareSchema(schema);

        const validate = await ajv.compileAsync(schema);
        const valid = validate(subject);
        const errors = this.enhanceConditionErrors(validate.errors as any[], schema);

        return new CheckResult(valid, 'JSON_SCHEMA_VALIDATION_ERROR', errors as any);
    }

    /**
     * Add Context
     *
     * @param {any} subject - subject
     * @param {any} context - new context
     * @returns {any} - subject
     */
    public addContextInSubject(subject: any, context: string): any {
        if (subject['@context']) {
            if (Array.isArray(subject['@context'])) {
                subject['@context'].push(context);
            } else {
                subject['@context'] = [subject['@context'], context];
            }
        } else {
            subject['@context'] = [context];
        }
        return subject
    }

    /**
     * Add Context
     *
     * @param {any} subject - subject
     * @returns {any} - subject
     */
    public addDryRunContext(subject: any, context?: string[]): any {
        if (!subject || typeof subject !== 'object') {
            return subject;
        }

        if (Array.isArray(subject)) {
            for (const subjectItem of subject) {
                this.addDryRunContext(subjectItem, context);
            }
            return subject;
        }

        if (!subject.type) {
            return subject;
        }

        subject['@context'] = context || [`schema:${subject.type}`];

        for (const value of Object.values(subject)) {
            this.addDryRunContext(value, subject['@context']);
        }

        return subject;
    }

    /**
     * Load schema by URI
     * @param uri URI
     * @returns Schema
     */
    public async loadSchema(uri: string) {
        try {
            let response: any;
            if (uri.startsWith(IPFS.IPFS_PROTOCOL)) {
                const cidMatches = uri.match(IPFS.CID_PATTERN);
                response = JSON.parse(
                    Buffer.from(
                        await IPFS.getFile(
                            (cidMatches && cidMatches[0]) || '',
                            'raw',
                            IPFS.DEFAULT_OPTIONS
                        )
                    ).toString()
                );
            } else {
                response = (await axios.get(uri)).data;
            }
            return response;
        } catch (err) {
            throw new Error('Can not resolve reference: ' + uri);
        }
    }

    /**
     * Create Ed25519 Suite by DID
     *
     * @param {any} verificationMethod - Verification Method
     *
     * @returns {Ed25519Signature2018} - Ed25519Signature2018
     */
    public async createEd25519Suite(verificationMethod: KeyPairOptions): Promise<Ed25519Signature2018> {
        const key = await Ed25519VerificationKey2018.from(verificationMethod);
        return new Ed25519Signature2018({ key });
    }

    /**
     * Create BBS Suite by DID
     *
     * @param {any} verificationMethod - Verification Method
     *
     * @returns {BbsBlsSignature2020} - BbsBlsSignature2020
     */
    public async createBBSSuite(verificationMethod: KeyPairOptions): Promise<BbsBlsSignature2020> {
        const key = await Bls12381G2KeyPair.from(verificationMethod);
        return new BbsBlsSignature2020({ key });
    }

    /**
     * Issue VC Document
     *
     * @param {HcsVcDocument<T>} vcDocument - VC Document
     * @param {Ed25519Signature2018} suite - suite
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {HcsVcDocument<T>} - VC Document
     */
    public async issue(
        vcDocument: VcDocument,
        suite: Ed25519Signature2018 | BbsBlsSignature2020,
        documentLoader: DocumentLoaderFunction
    ): Promise<VcDocument> {
        const vc: any = vcDocument.getDocument();
        ContextHelper.clearContext(vc);
        const verifiableCredential = await vcjs.createVerifiableCredential({
            credential: vc,
            suite,
            documentLoader,
        });
        if (
            suite instanceof BbsBlsSignature2020 &&
            verifiableCredential.proof?.type
        ) {
            verifiableCredential.proof.type = SignatureType.BbsBlsSignature2020;
        }
        vcDocument.proofFromJson(verifiableCredential);
        return vcDocument;
    }

    /**
     * Issue VP Document
     *
     * @param {HcsVpDocument} vpDocument - VP Document
     * @param {Ed25519Signature2018} suite - suite
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {HcsVpDocument} - VP Document
     */
    public async issuePresentation(
        vpDocument: VpDocument,
        suite: Ed25519Signature2018,
        documentLoader: DocumentLoaderFunction
    ): Promise<VpDocument> {
        const vp = vpDocument.toJsonTree();
        const verifiablePresentation = await vcjs.createVerifiablePresentation({
            presentation: vp,
            challenge: '123',
            suite,
            documentLoader,
        });
        vpDocument.proofFromJson(verifiablePresentation);
        return vpDocument;
    }

    /**
     * Create Suite by Method
     *
     * @param {SignatureType} type - Signature type
     *
     * @returns {Ed25519Signature2018 | BbsBlsSignature2020} - Ed25519Signature2018 | BbsBlsSignature2020
     */
    public async createSuiteByMethod(
        didDocument: CommonDidDocument,
        type: SignatureType
    ): Promise<Ed25519Signature2018 | BbsBlsSignature2020> {
        switch (type) {
            case SignatureType.BbsBlsSignature2020: {
                const verificationMethod = didDocument.getMethodByType(HederaBBSMethod.TYPE);
                if (!verificationMethod) {
                    throw new Error('Verification method not found.');
                }
                if (!verificationMethod.hasPrivateKey()) {
                    throw new Error('Private key not found.');
                }
                const option: any = verificationMethod.toObject(true);
                return this.createBBSSuite(option);
            }
            default: {
                const verificationMethod = didDocument.getMethodByType(HederaEd25519Method.TYPE);
                if (!verificationMethod) {
                    throw new Error('Verification method not found.');
                }
                if (!verificationMethod.hasPrivateKey()) {
                    throw new Error('Private key not found.');
                }
                const option: any = verificationMethod.toObject(true);
                return this.createEd25519Suite(option);
            }
        }
    }

    /**
     * Generate verification method by Hedera key
     *
     * @param {ISuiteOptions} suiteOptions - Suite Options (DID, Private Key, Signature Type)
     *
     * @returns {HederaDidDocument} - DID Document
     */
    public async generateDid(suiteOptions: ISuiteOptions): Promise<HederaDidDocument> {
        return await HederaDidDocument.generateByDid(suiteOptions.did, suiteOptions.key);
    }

    /**
     * Create VC Document
     *
     * @param {ICredentialSubject} subject - Credential Object
     * @param {CommonDidDocument} didDocument - DID Document
     * @param {SignatureType} signatureType - Signature type (Ed25519Signature2018, BbsBlsSignature2020)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     */
    public async createVerifiableCredential(
        subject: ICredentialSubject,
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const vcSubject = VcSubject.create(subject);
        const vc = new VcDocument(signatureType);
        vc.addCredentialSubject(vcSubject);
        vc.addContexts(subject['@context']);
        vc.addContexts(this.schemaContext);
        if (documentOptions && documentOptions.group) {
            vc.setIssuer(new Issuer(didDocument.getDid(), documentOptions.group.groupId));
            vc.addType(documentOptions.group.type);
            vc.addContext(documentOptions.group.context);
        } else {
            vc.setIssuer(new Issuer(didDocument.getDid()));
        }
        if (documentOptions?.evidenceContext) {
            vc.addContext(documentOptions.evidenceContext);
        }
        if (documentOptions?.evidence?.length) {
            for (const entry of documentOptions.evidence) {
                vc.addEvidence(entry);
            }
        }
        return await this.issueVerifiableCredential(vc, didDocument, signatureType, documentOptions);
    }

    /**
     * Create VC Document
     *
     * @param {VcDocument} verifiableCredential - VC Document
     * @param {CommonDidDocument} didDocument - DID Document
     * @param {SignatureType} signatureType - Signature type (Ed25519Signature2018, BbsBlsSignature2020)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     */
    public async issueVerifiableCredential(
        verifiableCredential: VcDocument,
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const id = this.generateUUID(documentOptions);
        const suite = await this.createSuiteByMethod(didDocument, signatureType);
        verifiableCredential.setId(id);
        verifiableCredential.setIssuanceDate(TimestampUtils.now());
        verifiableCredential.setProof(null);
        return await this.issue(verifiableCredential, suite, this.loader);
    }

    /**
     * Create VP Document
     *
     * @param {VcDocument[]} vcs - VC Documents
     * @param {ISuiteOptions} suiteOptions - Suite Options (Issuer, Private Key)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VpDocument} - VP Document
     */
    public async createVerifiablePresentation(
        vcs: VcDocument[],
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VpDocument> {
        const id: string = this.generateUUID(documentOptions);
        const suite = await this.createSuiteByMethod(didDocument, SignatureType.Ed25519Signature2018) as Ed25519Signature2018;
        const vp = new VpDocument();
        vp.setId(id);
        vp.addVerifiableCredentials(vcs);
        return await this.issuePresentation(vp, suite, this.loader);
    }
}
