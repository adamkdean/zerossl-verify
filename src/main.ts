// Copyright 2022 Adam K Dean <adamkdean@googlemail.com>
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

import express from 'express'

const app = express()
const port = process.env.HTTP_PORT || 8000

app.listen(port, () => console.log(`Listening on port ${port}`))
