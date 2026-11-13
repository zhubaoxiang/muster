export namespace model {
	
	export class Asset {
	    id: number;
	    host: string;
	    port: number;
	    scheme: string;
	    status: number;
	    title: string;
	    server: string;
	    fingerprint: string[];
	    taskId: string;
	    // Go type: time
	    firstSeen: any;
	    // Go type: time
	    lastSeen: any;
	
	    static createFrom(source: any = {}) {
	        return new Asset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.scheme = source["scheme"];
	        this.status = source["status"];
	        this.title = source["title"];
	        this.server = source["server"];
	        this.fingerprint = source["fingerprint"];
	        this.taskId = source["taskId"];
	        this.firstSeen = this.convertValues(source["firstSeen"], null);
	        this.lastSeen = this.convertValues(source["lastSeen"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScanRequest {
	    targets: string[];
	    ports: number[];
	    concurrency: number;
	    allowPublic: boolean;
	    mode: string;
	    fullRange: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ScanRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.targets = source["targets"];
	        this.ports = source["ports"];
	        this.concurrency = source["concurrency"];
	        this.allowPublic = source["allowPublic"];
	        this.mode = source["mode"];
	        this.fullRange = source["fullRange"];
	    }
	}
	export class Settings {
	    whitelist: string;
	    allowPublic: boolean;
	    maxRate: number;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.whitelist = source["whitelist"];
	        this.allowPublic = source["allowPublic"];
	        this.maxRate = source["maxRate"];
	    }
	}

}

