import axios from "axios";
import { Command } from "commander";
import crypto from "crypto";
import { XMLParser } from "fast-xml-parser";
import fs from "fs";
import path from "path";
import unzip from "unzip-stream";
import { handleAuthRotation } from "./utils/authUtils.mjs";
import {
  getBinaryInformMsg,
  getBinaryInitMsg,
  getDecryptionKey,
} from "./utils/msgUtils.mjs";
const parser = new XMLParser();
const getLatestVersion = async (region, model) => {
  return axios
    .get(
      `https://fota-cloud-dn.ospserver.net/firmware/${region}/${model}/version.xml`,
    )
    .then((res) => {
      const [pda, csc, modem] = parser
        .parse(res.data)
        .versioninfo.firmware.version.latest.split("/");
      return { pda, csc, modem };
    });
};
const main = async (region, model, imei) => {
  console.log(`\nModel: ${model}\nRegion: ${region}`);
  const { pda, csc, modem } = await getLatestVersion(region, model);
  console.log(
    `\nLatest version:\nPDA: ${pda}\nCSC: ${csc}\nMODEM: ${modem || "N/A"}`,
  );
  const nonce = { encrypted: "", decrypted: "" };
  const headers = { "User-Agent": "Kies2.0_FUS" };
  const handleHeaders = (responseHeaders) => {
    if (responseHeaders.nonce != null) {
      const { Authorization, nonce: newNonce } =
        handleAuthRotation(responseHeaders);
      Object.assign(nonce, newNonce);
      headers.Authorization = Authorization;
    }
    const sessionID = responseHeaders["set-cookie"]
      ?.find((cookie) => cookie.startsWith("JSESSIONID"))
      ?.split(";")[0];
    if (sessionID != null) {
      headers.Cookie = sessionID;
    }
  };
  await axios
    .post("https://neofussvr.sslcs.cdngc.net/NF_DownloadGenerateNonce.do", "", {
      headers: {
        Authorization:
          'FUS nonce="", signature="", nc="", type="", realm="", newauth="1"',
        "User-Agent": "Kies2.0_FUS",
        Accept: "application/xml",
      },
    })
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    });
  const {
    binaryByteSize,
    binaryDescription,
    binaryFilename,
    binaryLogicValue,
    binaryModelPath,
    binaryOSVersion,
    binaryVersion,
  } = await axios
    .post(
      "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInform.do",
      getBinaryInformMsg(
        `${pda}/${csc}/${modem || pda}/${pda}`,
        region,
        model,
        nonce.decrypted,
        imei,
      ),
      {
        headers: {
          ...headers,
          Accept: "application/xml",
          "Content-Type": "application/xml",
        },
      },
    )
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    })
    .then((res) => {
      const parsedInfo = parser.parse(res.data);
      return {
        binaryByteSize: parsedInfo.FUSMsg.FUSBody.Put.BINARY_BYTE_SIZE.Data,
        binaryDescription:
          parsedInfo.FUSMsg.FUSBody.Put.DESCRIPTION.Data || "N/A",
        binaryFilename: parsedInfo.FUSMsg.FUSBody.Put.BINARY_NAME.Data,
        binaryLogicValue:
          parsedInfo.FUSMsg.FUSBody.Put.LOGIC_VALUE_FACTORY.Data,
        binaryModelPath: parsedInfo.FUSMsg.FUSBody.Put.MODEL_PATH.Data,
        binaryOSVersion: parsedInfo.FUSMsg.FUSBody.Put.CURRENT_OS_VERSION.Data,
        binaryVersion: parsedInfo.FUSMsg.FUSBody.Results.LATEST_FW_VERSION.Data,
      };
    });
  console.log(
    `\nOS: ${binaryOSVersion}\nFilename: ${binaryFilename}\nSize: ${binaryByteSize} bytes\nLogic Value: ${binaryLogicValue}\nDescription: ${binaryDescription}`,
  );
  const decryptionKey = getDecryptionKey(binaryVersion, binaryLogicValue);
  await axios
    .post(
      "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInitForMass.do",
      getBinaryInitMsg(binaryFilename, nonce.decrypted),
      {
        headers: {
          ...headers,
          Accept: "application/xml",
          "Content-Type": "application/xml",
        },
      },
    )
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    });
  const binaryDecipher = crypto.createDecipheriv(
    "aes-128-ecb",
    decryptionKey,
    null,
  );
  await axios
    .get(
      `https://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file=${binaryModelPath}${binaryFilename}`,
      { headers, responseType: "stream" },
    )
    .then((res) => {
      const outputFolder = `${process.cwd()}/${model}_${region}/`;
      fs.mkdirSync(outputFolder, { recursive: true });
      let downloadedSize = 0;
      return res.data
        .on("data", (buffer) => {
          downloadedSize += buffer.length;
        })
        .pipe(binaryDecipher)
        .pipe(unzip.Parse())
        .on("entry", (entry) => {
          entry
            .pipe(fs.createWriteStream(path.join(outputFolder, entry.path)))
            .on("finish", () => {
              if (downloadedSize === binaryByteSize) {
                console.log("\nDownload completed");
                process.exit();
              }
            });
        });
    });
};
const program = new Command();
program
  .requiredOption("-m, --model <model>", "Model")
  .requiredOption("-r, --region <region>", "Region")
  .requiredOption("-i, --imei <imei>", "IMEI/Serial Number")
  .parse(process.argv);
const options = program.opts();
main(options.region, options.model, options.imei);
