// export const isNode = typeof process !== 'undefined' &&
//     process.versions != null &&
//     process.versions.node != null;
//
// export const isDeno = typeof Deno !== 'undefined';
//
// export const isBrowser = typeof globalThis !== 'undefined' &&
//     typeof (globalThis as any).document !== 'undefined';
//
export const isNode = false
export const isDeno = false
export const isBrowser = true
// console.log('ENVs', { isBrowser, isDeno, isNode });//TODO remove

// TODO refactor
