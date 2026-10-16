import crypto from 'node:crypto';

export function createDraw(participants) {
  if (!Array.isArray(participants) || participants.length < 2) throw new Error('At least two participants are required.');
  const shuffled = [...participants];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const random = crypto.randomInt(index + 1);
    [shuffled[index], shuffled[random]] = [shuffled[random], shuffled[index]];
  }
  return shuffled.map((giver, index) => ({
    giver,
    recipient: shuffled[(index + 1) % shuffled.length]
  }));
}
