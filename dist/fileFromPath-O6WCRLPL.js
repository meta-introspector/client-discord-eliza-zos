import {
  ReadableStream,
  require_node_domexception
} from "./chunk-5UROAN6G.js";
import {
  __toESM
} from "./chunk-PLDDJCW6.js";

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/fileFromPath.js
var import_node_domexception = __toESM(require_node_domexception(), 1);
import { statSync, createReadStream, promises as fs } from "fs";
import { basename } from "path";

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/isFunction.js
var isFunction = (value) => typeof value === "function";

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/blobHelpers.js
var CHUNK_SIZE = 65536;
async function* clonePart(part) {
  const end = part.byteOffset + part.byteLength;
  let position = part.byteOffset;
  while (position !== end) {
    const size = Math.min(end - position, CHUNK_SIZE);
    const chunk = part.buffer.slice(position, position + size);
    position += chunk.byteLength;
    yield new Uint8Array(chunk);
  }
}
async function* consumeNodeBlob(blob) {
  let position = 0;
  while (position !== blob.size) {
    const chunk = blob.slice(position, Math.min(blob.size, position + CHUNK_SIZE));
    const buffer = await chunk.arrayBuffer();
    position += buffer.byteLength;
    yield new Uint8Array(buffer);
  }
}
async function* consumeBlobParts(parts, clone = false) {
  for (const part of parts) {
    if (ArrayBuffer.isView(part)) {
      if (clone) {
        yield* clonePart(part);
      } else {
        yield part;
      }
    } else if (isFunction(part.stream)) {
      yield* part.stream();
    } else {
      yield* consumeNodeBlob(part);
    }
  }
}
function* sliceBlob(blobParts, blobSize, start = 0, end) {
  end !== null && end !== void 0 ? end : end = blobSize;
  let relativeStart = start < 0 ? Math.max(blobSize + start, 0) : Math.min(start, blobSize);
  let relativeEnd = end < 0 ? Math.max(blobSize + end, 0) : Math.min(end, blobSize);
  const span = Math.max(relativeEnd - relativeStart, 0);
  let added = 0;
  for (const part of blobParts) {
    if (added >= span) {
      break;
    }
    const partSize = ArrayBuffer.isView(part) ? part.byteLength : part.size;
    if (relativeStart && partSize <= relativeStart) {
      relativeStart -= partSize;
      relativeEnd -= partSize;
    } else {
      let chunk;
      if (ArrayBuffer.isView(part)) {
        chunk = part.subarray(relativeStart, Math.min(partSize, relativeEnd));
        added += chunk.byteLength;
      } else {
        chunk = part.slice(relativeStart, Math.min(partSize, relativeEnd));
        added += chunk.size;
      }
      relativeEnd -= partSize;
      relativeStart = 0;
      yield chunk;
    }
  }
}

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/Blob.js
var __classPrivateFieldGet = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var _Blob_parts;
var _Blob_type;
var _Blob_size;
var Blob = class _Blob {
  constructor(blobParts = [], options = {}) {
    _Blob_parts.set(this, []);
    _Blob_type.set(this, "");
    _Blob_size.set(this, 0);
    options !== null && options !== void 0 ? options : options = {};
    if (typeof blobParts !== "object" || blobParts === null) {
      throw new TypeError("Failed to construct 'Blob': The provided value cannot be converted to a sequence.");
    }
    if (!isFunction(blobParts[Symbol.iterator])) {
      throw new TypeError("Failed to construct 'Blob': The object must have a callable @@iterator property.");
    }
    if (typeof options !== "object" && !isFunction(options)) {
      throw new TypeError("Failed to construct 'Blob': parameter 2 cannot convert to dictionary.");
    }
    const encoder = new TextEncoder();
    for (const raw of blobParts) {
      let part;
      if (ArrayBuffer.isView(raw)) {
        part = new Uint8Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
      } else if (raw instanceof ArrayBuffer) {
        part = new Uint8Array(raw.slice(0));
      } else if (raw instanceof _Blob) {
        part = raw;
      } else {
        part = encoder.encode(String(raw));
      }
      __classPrivateFieldSet(this, _Blob_size, __classPrivateFieldGet(this, _Blob_size, "f") + (ArrayBuffer.isView(part) ? part.byteLength : part.size), "f");
      __classPrivateFieldGet(this, _Blob_parts, "f").push(part);
    }
    const type = options.type === void 0 ? "" : String(options.type);
    __classPrivateFieldSet(this, _Blob_type, /^[\x20-\x7E]*$/.test(type) ? type : "", "f");
  }
  static [(_Blob_parts = /* @__PURE__ */ new WeakMap(), _Blob_type = /* @__PURE__ */ new WeakMap(), _Blob_size = /* @__PURE__ */ new WeakMap(), Symbol.hasInstance)](value) {
    return Boolean(value && typeof value === "object" && isFunction(value.constructor) && (isFunction(value.stream) || isFunction(value.arrayBuffer)) && /^(Blob|File)$/.test(value[Symbol.toStringTag]));
  }
  get type() {
    return __classPrivateFieldGet(this, _Blob_type, "f");
  }
  get size() {
    return __classPrivateFieldGet(this, _Blob_size, "f");
  }
  slice(start, end, contentType) {
    return new _Blob(sliceBlob(__classPrivateFieldGet(this, _Blob_parts, "f"), this.size, start, end), {
      type: contentType
    });
  }
  async text() {
    const decoder = new TextDecoder();
    let result = "";
    for await (const chunk of consumeBlobParts(__classPrivateFieldGet(this, _Blob_parts, "f"))) {
      result += decoder.decode(chunk, { stream: true });
    }
    result += decoder.decode();
    return result;
  }
  async arrayBuffer() {
    const view = new Uint8Array(this.size);
    let offset = 0;
    for await (const chunk of consumeBlobParts(__classPrivateFieldGet(this, _Blob_parts, "f"))) {
      view.set(chunk, offset);
      offset += chunk.length;
    }
    return view.buffer;
  }
  stream() {
    const iterator = consumeBlobParts(__classPrivateFieldGet(this, _Blob_parts, "f"), true);
    return new ReadableStream({
      async pull(controller) {
        const { value, done } = await iterator.next();
        if (done) {
          return queueMicrotask(() => controller.close());
        }
        controller.enqueue(value);
      },
      async cancel() {
        await iterator.return();
      }
    });
  }
  get [Symbol.toStringTag]() {
    return "Blob";
  }
};
Object.defineProperties(Blob.prototype, {
  type: { enumerable: true },
  size: { enumerable: true },
  slice: { enumerable: true },
  stream: { enumerable: true },
  text: { enumerable: true },
  arrayBuffer: { enumerable: true }
});

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/File.js
var __classPrivateFieldSet2 = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var __classPrivateFieldGet2 = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _File_name;
var _File_lastModified;
var File = class extends Blob {
  constructor(fileBits, name, options = {}) {
    super(fileBits, options);
    _File_name.set(this, void 0);
    _File_lastModified.set(this, 0);
    if (arguments.length < 2) {
      throw new TypeError(`Failed to construct 'File': 2 arguments required, but only ${arguments.length} present.`);
    }
    __classPrivateFieldSet2(this, _File_name, String(name), "f");
    const lastModified = options.lastModified === void 0 ? Date.now() : Number(options.lastModified);
    if (!Number.isNaN(lastModified)) {
      __classPrivateFieldSet2(this, _File_lastModified, lastModified, "f");
    }
  }
  static [(_File_name = /* @__PURE__ */ new WeakMap(), _File_lastModified = /* @__PURE__ */ new WeakMap(), Symbol.hasInstance)](value) {
    return value instanceof Blob && value[Symbol.toStringTag] === "File" && typeof value.name === "string";
  }
  get name() {
    return __classPrivateFieldGet2(this, _File_name, "f");
  }
  get lastModified() {
    return __classPrivateFieldGet2(this, _File_lastModified, "f");
  }
  get webkitRelativePath() {
    return "";
  }
  get [Symbol.toStringTag]() {
    return "File";
  }
};

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/isPlainObject.js
var getType = (value) => Object.prototype.toString.call(value).slice(8, -1).toLowerCase();
function isPlainObject(value) {
  if (getType(value) !== "object") {
    return false;
  }
  const pp = Object.getPrototypeOf(value);
  if (pp === null || pp === void 0) {
    return true;
  }
  const Ctor = pp.constructor && pp.constructor.toString();
  return Ctor === Object.toString();
}
var isPlainObject_default = isPlainObject;

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/isFile.js
var isFile = (value) => value instanceof File;

// ../../node_modules/together-ai/node_modules/formdata-node/lib/esm/fileFromPath.js
var __classPrivateFieldSet3 = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var __classPrivateFieldGet3 = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _FileFromPath_path;
var _FileFromPath_start;
var MESSAGE = "The requested file could not be read, typically due to permission problems that have occurred after a reference to a file was acquired.";
var FileFromPath = class _FileFromPath {
  constructor(input) {
    _FileFromPath_path.set(this, void 0);
    _FileFromPath_start.set(this, void 0);
    __classPrivateFieldSet3(this, _FileFromPath_path, input.path, "f");
    __classPrivateFieldSet3(this, _FileFromPath_start, input.start || 0, "f");
    this.name = basename(__classPrivateFieldGet3(this, _FileFromPath_path, "f"));
    this.size = input.size;
    this.lastModified = input.lastModified;
  }
  slice(start, end) {
    return new _FileFromPath({
      path: __classPrivateFieldGet3(this, _FileFromPath_path, "f"),
      lastModified: this.lastModified,
      size: end - start,
      start
    });
  }
  async *stream() {
    const { mtimeMs } = await fs.stat(__classPrivateFieldGet3(this, _FileFromPath_path, "f"));
    if (mtimeMs > this.lastModified) {
      throw new import_node_domexception.default(MESSAGE, "NotReadableError");
    }
    if (this.size) {
      yield* createReadStream(__classPrivateFieldGet3(this, _FileFromPath_path, "f"), {
        start: __classPrivateFieldGet3(this, _FileFromPath_start, "f"),
        end: __classPrivateFieldGet3(this, _FileFromPath_start, "f") + this.size - 1
      });
    }
  }
  get [(_FileFromPath_path = /* @__PURE__ */ new WeakMap(), _FileFromPath_start = /* @__PURE__ */ new WeakMap(), Symbol.toStringTag)]() {
    return "File";
  }
};
function createFileFromPath(path, { mtimeMs, size }, filenameOrOptions, options = {}) {
  let filename;
  if (isPlainObject_default(filenameOrOptions)) {
    [options, filename] = [filenameOrOptions, void 0];
  } else {
    filename = filenameOrOptions;
  }
  const file = new FileFromPath({ path, size, lastModified: mtimeMs });
  if (!filename) {
    filename = file.name;
  }
  return new File([file], filename, {
    ...options,
    lastModified: file.lastModified
  });
}
function fileFromPathSync(path, filenameOrOptions, options = {}) {
  const stats = statSync(path);
  return createFileFromPath(path, stats, filenameOrOptions, options);
}
async function fileFromPath(path, filenameOrOptions, options) {
  const stats = await fs.stat(path);
  return createFileFromPath(path, stats, filenameOrOptions, options);
}
export {
  fileFromPath,
  fileFromPathSync,
  isFile
};
/*! Bundled license information:

formdata-node/lib/esm/blobHelpers.js:
  (*! Based on fetch-blob. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> & David Frank *)

formdata-node/lib/esm/Blob.js:
  (*! Based on fetch-blob. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> & David Frank *)
*/
//# sourceMappingURL=fileFromPath-O6WCRLPL.js.map