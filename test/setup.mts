import { register } from "node:module"
import { pathToFileURL } from "node:url"
register("./ts-resolver.mts", pathToFileURL("./test/"))
