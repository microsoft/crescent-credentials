const path = require('path');
const fs = require('fs');

const {
  MAX_SLD_NAME_LEN,
  MAX_TLD_NAME_LEN,
  MAX_RSA_SIG_LEN,
  MAX_RSA_KEY_LEN,
  MAX_TLD_RSA_DNSKEY_REC_LEN,
  MAX_TLD_ECDSA_DNSKEY_REC_LEN,
  MAX_SLD_RSA_DNSKEY_REC_LEN,
  MAX_SLD_ECDSA_DNSKEY_REC_LEN,
} = require('./constants.js');

const {
  strToDomainPair,
  rightPadArrayTo,
  strToWire,
  leftPadArrayTo,
  sha256pad,
  sha256withoutpad,
  tobitsarr,
  parseDSForOffset,
  packInputsForField,
  flattenEccSigAux,
} = require('./util.js');

const {buildSigWitness, proofOfECCKey, wordsToBytes} = require('./eccutil.js');

exports.makeDigest = function(key, ca) {
  // get top bytes of current timestamp
  const timestamp = [...Buffer.from(Date.now().toString(16).padStart(16, '0'), 'hex')].slice(0, 5);
  // build digest from key, ca, and current timestamp and return
  return wordsToBytes(sha256withoutpad(sha256pad(Buffer.concat([
    Buffer.from(key),
    Buffer.from(ca),
    Buffer.from(timestamp)
  ]))));
}

exports.makeInput = function(
  data_path,
  domain,
  pub_digest,
  tld_alg = 8,
  sld_alg = 8,
  managed = false,
) {
  var ret = {};
  const names = strToDomainPair(domain);

  if ((tld_alg != 8 && tld_alg != 13) || (sld_alg != 8 && sld_alg != 13)) {
    throw new Error('Invalid algorithm for generating input');
  }

  ret['sld_name'] = rightPadArrayTo(strToWire(names[0]), MAX_SLD_NAME_LEN);
  const raw_root_zsk = fs.readFileSync(
    path.join(data_path, names[1] + '-DS-KEY.dat'),
  );
  ret['root_zsk'] = rightPadArrayTo(raw_root_zsk, MAX_RSA_KEY_LEN);
  ret['root_zsk_len_bytes'] = [
    raw_root_zsk.length % 256,
    raw_root_zsk.length >> 8,
  ];
  // we directly compute pub_digest if it is managed!
  if (!managed) {
    ret['pub_digest'] = pub_digest;
  }

  const raw_tld_ds_rec = fs.readFileSync(
    path.join(data_path, names[1] + '-DS-REC.dat'),
  );
  const raw_tld_ds_sig = fs.readFileSync(
    path.join(data_path, names[1] + '-DS-SIG.dat'),
  );
  ret['tld_ds_sig'] = leftPadArrayTo(raw_tld_ds_sig, MAX_RSA_SIG_LEN);
  ret['tld_ds_sig_len'] = raw_tld_ds_sig.length;
  const tld_ds_recwpad = sha256pad(raw_tld_ds_rec);
  ret['tld_ds_prev_hash_bits'] = tobitsarr(
    sha256withoutpad(tld_ds_recwpad.slice(0, -128)),
  );
  ret['tld_ds_rec_suffix'] = rightPadArrayTo(tld_ds_recwpad.slice(-128), 128);
  ret['tld_ds_hash_offset'] = parseDSForOffset(tld_ds_recwpad);

  const raw_tld_dnskey_rec = fs.readFileSync(
    path.join(data_path, names[1] + '-DNSKEY-REC.dat'),
  );
  if (tld_alg == 8) {
    ret['tld_dnskey_rec'] = rightPadArrayTo(
      raw_tld_dnskey_rec,
      MAX_TLD_RSA_DNSKEY_REC_LEN,
    );
  } else if (tld_alg == 13) {
    ret['tld_dnskey_rec'] = rightPadArrayTo(
      raw_tld_dnskey_rec,
      MAX_TLD_ECDSA_DNSKEY_REC_LEN,
    );
  }
  ret['tld_dnskey_rec_len'] = raw_tld_dnskey_rec.length;
  const raw_tld_ksk = fs.readFileSync(
    path.join(data_path, names[1] + '-DNSKEY-KSK.dat'),
  );
  const raw_tld_dnskey_sig = fs.readFileSync(
    path.join(data_path, names[1] + '-DNSKEY-SIG.dat'),
  );
  ret['tld_ksk_len'] = raw_tld_ksk.length;
  if (tld_alg == 8) {
    ret['tld_ksk'] = rightPadArrayTo(
      raw_tld_ksk,
      MAX_TLD_NAME_LEN + 4 + MAX_RSA_KEY_LEN,
    );
    ret['tld_dnskey_sig'] = leftPadArrayTo(raw_tld_dnskey_sig, MAX_RSA_SIG_LEN);
    ret['tld_dnskey_sig_len'] = raw_tld_dnskey_sig.length;
  } else if (tld_alg == 13) {
    ret['tld_ksk'] = rightPadArrayTo(raw_tld_ksk, MAX_TLD_NAME_LEN + 4 + 64);
    ret['tld_dnskey_sig'] = flattenEccSigAux(
      buildSigWitness(
        raw_tld_dnskey_rec,
        raw_tld_dnskey_sig,
        raw_tld_ksk.slice(-64),
      ),
    );
  }

  const raw_sld_ds_rec = fs.readFileSync(
    path.join(data_path, names[0] + '-DS-REC.dat'),
  );
  const raw_sld_ds_key = fs.readFileSync(
    path.join(data_path, names[0] + '-DS-KEY.dat'),
  );
  const sld_ds_recwpad = sha256pad(raw_sld_ds_rec);
  ret['sld_ds_prev_hash_bits'] = tobitsarr(
    sha256withoutpad(sld_ds_recwpad.slice(0, -128)),
  );
  ret['sld_ds_rec_suffix'] = rightPadArrayTo(sld_ds_recwpad.slice(-128), 128);
  ret['sld_ds_hash_offset'] = parseDSForOffset(sld_ds_recwpad);
  const raw_sld_ds_sig = fs.readFileSync(
    path.join(data_path, names[0] + '-DS-SIG.dat'),
  );
  if (tld_alg == 8) {
    ret['sld_ds_key'] = rightPadArrayTo(raw_sld_ds_key, MAX_RSA_KEY_LEN);
    ret['sld_ds_key_len'] = raw_sld_ds_key.length;
    ret['sld_ds_sig'] = leftPadArrayTo(raw_sld_ds_sig, MAX_RSA_SIG_LEN);
    ret['sld_ds_sig_len'] = raw_sld_ds_sig.length;
  } else if (tld_alg == 13) {
    ret['sld_ds_key'] = rightPadArrayTo(raw_sld_ds_key, 64);
    ret['sld_ds_sig'] = flattenEccSigAux(
      buildSigWitness(
        raw_sld_ds_rec,
        raw_sld_ds_sig,
        raw_sld_ds_key.slice(-64),
      ),
    );
  }

  const raw_sld_ksk = fs.readFileSync(
    path.join(data_path, names[0] + '-DNSKEY-KSK.dat'),
  );
  if (sld_alg == 8) {
    ret['sld_ksk'] = rightPadArrayTo(
      raw_sld_ksk,
      MAX_SLD_NAME_LEN + 4 + MAX_RSA_KEY_LEN,
    );
    ret['sld_ksk_len'] = raw_sld_ksk.length;
  } else if (sld_alg == 13) {
    ret['sld_ksk'] = rightPadArrayTo(raw_sld_ksk, MAX_SLD_NAME_LEN + 4 + 64);
    ret['sld_ksk_len'] = raw_sld_ksk.length;
  }
  if (managed) {
    // add managed inputs (SLD DNSKEY and SLD TXT suffix, like DS)
    const raw_sld_dnskey_rec = fs.readFileSync(
      path.join(data_path, names[0] + '-DNSKEY-REC.dat'),
    );
    if (sld_alg == 8) {
      ret['sld_dnskey_rec'] = rightPadArrayTo(
        raw_sld_dnskey_rec,
        MAX_SLD_RSA_DNSKEY_REC_LEN,
      );
    } else if (sld_alg == 13) {
      ret['sld_dnskey_rec'] = rightPadArrayTo(
        raw_sld_dnskey_rec,
        MAX_SLD_ECDSA_DNSKEY_REC_LEN,
      );
    }
    ret['sld_dnskey_rec_len'] = raw_sld_dnskey_rec.length;
    const raw_sld_dnskey_sig = fs.readFileSync(
      path.join(data_path, names[0] + '-DNSKEY-SIG.dat'),
    );
    if (sld_alg == 8) {
      ret['sld_dnskey_sig'] = leftPadArrayTo(
        raw_sld_dnskey_sig,
        MAX_RSA_SIG_LEN,
      );
      ret['sld_dnskey_sig_len'] = raw_sld_dnskey_sig.length;
    } else if (sld_alg == 13) {
      ret['sld_dnskey_sig'] = flattenEccSigAux(
        buildSigWitness(
          raw_sld_dnskey_rec,
          raw_sld_dnskey_sig,
          raw_sld_ksk.slice(-64),
        ),
      );
    }

    const raw_sld_txt_rec = fs.readFileSync(
      path.join(data_path, names[0] + '-TXT-REC.dat'),
    );
    const raw_sld_txt_key = fs.readFileSync(
      path.join(data_path, names[0] + '-TXT-KEY.dat'),
    );
    const sld_txt_recwpad = sha256pad(raw_sld_txt_rec);
    ret['sld_txt_prev_hash_bits'] = tobitsarr(
      sha256withoutpad(sld_txt_recwpad.slice(0, -64)),
    );
    ret['sld_txt_rec_suffix'] = rightPadArrayTo(sld_txt_recwpad.slice(-64), 64);
    // get 43 bytes starting at byte 5 from sld_txt_rec_suffix as pub_digest
    ret['pub_digest'] = rightPadArrayTo(
      ret['sld_txt_rec_suffix'].slice(5, 48),
      43,
    );
    const raw_sld_txt_sig = fs.readFileSync(
      path.join(data_path, names[0] + '-TXT-SIG.dat'),
    );
    if (sld_alg == 8) {
      ret['sld_txt_key'] = rightPadArrayTo(raw_sld_txt_key, MAX_RSA_KEY_LEN);
      ret['sld_txt_key_len'] = raw_sld_txt_key.length;
      ret['sld_txt_sig'] = leftPadArrayTo(raw_sld_txt_sig, MAX_RSA_SIG_LEN);
      ret['sld_txt_sig_len'] = raw_sld_txt_sig.length;
    } else if (sld_alg == 13) {
      ret['sld_txt_key'] = rightPadArrayTo(raw_sld_txt_key, 64);
      ret['sld_txt_sig'] = flattenEccSigAux(
        buildSigWitness(raw_sld_txt_rec, raw_sld_txt_sig, raw_sld_txt_key),
      );
    }
  } else {
    if (sld_alg == 8) {
      const raw_sld_factors = fs.readFileSync(
        path.join(data_path, names[0] + '-DNSKEY-KSK-factors.dat'),
      );
      ret['sld_ksk_factors'] = [
        raw_sld_factors.toJSON().data.slice(0, 128),
        raw_sld_factors.toJSON().data.slice(128, 256),
      ];
    } else if (sld_alg == 13) {
      const raw_cst = fs.readFileSync(
        path.join(data_path, names[0] + '-DNSKEY-KSK-dlog.dat'),
      );
      const raw_pinfo = proofOfECCKey(raw_cst);
      ret["sld_ksk_priv_k"] = raw_pinfo.k;
      ret["sld_ksk_priv_addres_x"] = raw_pinfo.addres_x;
      ret["sld_ksk_priv_addres_y"] = raw_pinfo.addres_y;
      ret["sld_ksk_priv_addadva"] = raw_pinfo.addadva;
      ret["sld_ksk_priv_addadvb"] = raw_pinfo.addadvb;
      ret["sld_ksk_priv_Gadv_x"] = raw_pinfo.Gadv_x;
      ret["sld_ksk_priv_Gadv_y"] = raw_pinfo.Gadv_y;
    }
  }

  ret['packed_pub_inputs'] = packInputsForField([
    ret['sld_name'],
    ret['root_zsk'],
    ret['root_zsk_len_bytes'],
    ret['pub_digest'],
  ]);

  return ret;
};

exports.writeInput = function(
  data_path,
  output_path,
  domain,
  pub_digest,
  tld_alg = 8,
  sld_alg = 8,
  managed = false,
) {
  const input = exports.makeInput(
    data_path,
    domain,
    pub_digest, // dummy values
    tld_alg,
    sld_alg,
    managed,
  );
  fs.writeFileSync(
    output_path,
    JSON.stringify(input, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value,
    ),
  );
};