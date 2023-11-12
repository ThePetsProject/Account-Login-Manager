import mongoose from 'mongoose'
import fs from 'fs'

export const mongoConnect = async (): Promise<string> => {
  const mongooseOptions: mongoose.ConnectOptions = {}
  const mongoStrinfFilePath = process.env.VAULT_SECRETS_FILE_PATH
  const mongoString = fs
    .readFileSync(`${mongoStrinfFilePath}mongostring.txt`)
    .toString()
  return new Promise((resolve, reject) => {
    mongoose.connect(mongoString, mongooseOptions).then(
      () => {
        console.log('Connected to Mongo')
        return resolve('')
      },
      (err) => {
        console.error(`Error! --> ${err}`)
        return reject(err)
      }
    )
  })
}
