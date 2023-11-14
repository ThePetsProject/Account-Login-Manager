import { UserType } from '@src/infrastructure/database/models/user'
import { Router } from 'express'
import mongoose from 'mongoose'
import { Request, Response } from 'express'
import Joi from 'joi'
import axios, { AxiosError } from 'axios'

interface JwtResponse {
  accToken: string
  refToken: string
}

export type LoginRouteFnType = (
  router: Router,
  user: mongoose.Model<UserType>
) => Router

export const loginHandler = async (
  user: mongoose.Model<UserType>,
  req: Request,
  res: Response
): Promise<Response> => {
  const { email, password } = req.body
  const logPrefix = `[ACC-LOGIN-MANAGER][${email}]`

  console.info(`${logPrefix} Trying login for ${email}`)

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  })

  const { error, value } = schema.validate({ email, password })

  if (error) {
    console.error(`${logPrefix}[SCHEMA_ERROR][ERROR_MESSAGE] ${error.message}`)
    return res.status(400).send()
  }

  const userExists = await user.findOne({
    email: email.toLowerCase().trim(),
  })

  if (!userExists) {
    console.error(
      `${logPrefix}[USER_ERROR][USER_NOT_FOUND] User ${email} not found`
    )
    return res.status(404).send()
  }

  console.info(`${logPrefix} User found. Checking password`)

  const pwdCheck = await userExists.checkPassword(password)

  if (!pwdCheck) {
    console.error(
      `${logPrefix}[USER_ERROR][WRONG_PASSWORD] Wrong password for ${email}`
    )
    return res.status(401).send()
  }

  console.info(`${logPrefix} User logged. Setting JWT`)

  const jwtUrl = `${process.env.JWT_MANAGER_URL}/${process.env.JWT_MANAGER_SET_PATH}`

  console.info(`${logPrefix} Calling JWT Manager at ${jwtUrl}`)

  const axiosConfig = {
    method: 'post',
    url: jwtUrl,
    data: {
      email,
    },
  }
  return axios
    .request<JwtResponse>(axiosConfig)
    .then((response) => {
      const { accToken, refToken } = response.data
      console.info(`${logPrefix} JWT set. Sending response`)
      return res.status(200).send({
        accToken,
        refToken,
      })
    })
    .catch((error: AxiosError) => {
      console.error(`${logPrefix}[AXIOS_ERROR][ERROR_MESSAGE] ${error.message}`)
      console.error(`${logPrefix}[AXIOS_ERROR][ERROR_CODE] ${error.code}`)
      return res.status(500).send({
        message: error.message,
      })
    })
}

export const loginRoute: LoginRouteFnType = (
  router: Router,
  user: mongoose.Model<UserType>
): Router => {
  /**
   * @swagger
   * /login:
   *   post:
   *     summary: Login user
   *     description: Login user
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               email:
   *                 type: string
   *                 description: User email
   *               password:
   *                 type: string
   *                 description: User password
   *             required:
   *               - email
   *               - password
   *     responses:
   *       '200':
   *         description: User logged in
   *       '400':
   *         description: Bad request
   *       '401':
   *         description: Unauthorized
   *       '404':
   *         description: User not found
   *       '500':
   *         description: Internal server error
   *     tags:
   *       - Login
   *     security:
   *       - bearerAuth: []
   */
  return router.post('/', (req, res) => loginHandler(user, req, res))
}
