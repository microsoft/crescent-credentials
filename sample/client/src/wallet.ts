/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.
*/

// BACKGROUND ********************************************************************************************************************

// 1. Init Wallet

// 2. Handlie Import from content new 'pending' Card from JWt, issuer-url, friendly namei

// 3. Handlle disclosure request from content filtering by disclosure type

// POPUP ************************************************************************************************************************

// const wallet = new Wallet()

// content.ts
// wallet.importCard(jwt, issuerUrl, friendlyName)
// wallet.requestDisclosure(disclosureType)

// backgrount.ts
//
// _requestPrepare -> clientHelper
// _requestStatus -> clientHelper
// _requestShowProof -> clientHelper
// _updateStatus -> popup
// _prepared -> popup
// _error -> popup
// _importCard -> popup

// popup.ts
// wallet.acceptCard(disclosureType, data)

/*
    Card States:
    - pending (credential received from content, pending approval from user)
    - preparing (client helper is preparing the proof)
    - prepared (proof is ready)
    - disclosable (ready for user to disclose specific data)
    - error (something went wrong awaiting user action)

    content->background: importCard(jwt, issuerUrl, friendlyName)
    background->popup: importCard(jwt, issuerUrl, friendlyName)
    popup->background: acceptCard(disclosureType, data)

*/
