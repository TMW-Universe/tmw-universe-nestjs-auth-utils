import {
  DynamicModule,
  Global,
  Logger,
  Module,
  Provider,
} from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import axios, { AxiosError } from "axios";
import * as https from "https";

export const TMWU_AUTH_PROVIDER = "TMW_UNIVERSE_AUTH_PROVIDER";

type Options = {
  authHost: string;
  domain: string;
  configRetryDelay?: number;
};

@Global()
@Module({})
export class AuthModule {
  static async register(options: Options): Promise<DynamicModule> {
    let publicKey: string | null = null;

    let attempt = 1;
    do {
      try {
        const response = await axios.get<{ publicKey: string }>(
          `${options.authHost}/api/third-api/keys/public-key`,
          {
            httpsAgent: new https.Agent({
              rejectUnauthorized: false,
            }),
          }
        );
        publicKey = response?.data.publicKey;
        if (publicKey && typeof publicKey === "string") {
          Logger.log("Public key retrieved", "TMWU Auth");
        }
      } catch (e) {
        const error = e as AxiosError;
        Logger.warn(
          `${attempt > 1 ? `(${attempt}) ` : ""}Public key retrieve failed (${
            error.code
          }): ${error.cause}`,
          "TMWU Auth"
        );
        attempt++;
        await new Promise((r) =>
          setTimeout(r, options.configRetryDelay ?? 10000)
        );
      }
    } while (publicKey === null);

    const providers: Provider[] = [
      {
        provide: TMWU_AUTH_PROVIDER,
        useValue: { publicKey, domain: options.domain },
      },
    ];

    return {
      module: AuthModule,
      providers,
      imports: [
        JwtModule.register({
          global: true,
          publicKey,
        }),
      ],
      exports: [TMWU_AUTH_PROVIDER],
    };
  }
}
